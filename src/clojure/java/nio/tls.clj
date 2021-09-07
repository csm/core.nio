(ns clojure.java.nio.tls
  (:require [clojure.core.async :as async]
            [clojure.java.nio :as nio]
            [clojure.spec.alpha :as s]
            [cognitect.anomalies :as anomalies])
  (:import (javax.net.ssl SSLEngine SSLEngineResult$HandshakeStatus SSLEngineResult$Status SSLEngineResult)
           (java.nio.channels AsynchronousSocketChannel)
           (java.nio ByteBuffer)
           (java.util List Random LinkedList)))

(defprotocol Handshake
  (-handshake [this]
    "Run the handshake. Returns a channel that yields a value when
    the handshake completes, or an anomaly on error."))

(def ^:dynamic *lock-id* nil)

(defn- read-fully
  "Fully consume network bytes until buffer is filled."
  [socket buffer]
  (async/go-loop []
    (when (.hasRemaining buffer)
      (let [result (async/<! (nio/read socket {:buffer buffer}))]
        (if (s/valid? ::anomalies/anomaly result)
          result
          (recur))))))

(defn- read-tls-record
  "Reads a single, full TLS record from socket.

  This reads enough to get a full record header, then uses the
  length field read to read the rest of the TLS record."
  [socket buffer]
  (async/go
    ; consume the record header
    ; |type(8)|version(16)|length(16)|
    (let [res (async/<! (read-fully socket (.limit (.slice buffer) 5)))]
      (if (s/valid? ::anomalies/anomaly res)
        res
        (let [_ (.get buffer)      ; content type
              _ (.getShort buffer) ; version number
              length (.getShort buffer)
              res (async/<! (read-fully socket (.limit buffer (+ (.position buffer) length))))]
          (when (s/valid? ::anomalies/anomaly res)
            res))))))

(defn- write-tls-record
  [socket buffer]
  (async/go
    (let [length (.getShort (.slice buffer) 3)]
      (if (not= (.remaining buffer) (+ length 5))
        {::anomalies/category ::anomalies/incorrect
         ::anomalies/message "Buffer is not the right size for a TLS record."}
        (loop []
          (when (.hasRemaining buffer)
            (let [res (async/<! (nio/write socket buffer {}))]
              (if (s/valid? ::anomalies/anomaly res)
                res
                (recur)))))))))

(defmacro async-locking
  "A reentrant, asynchronous lock."
  [lock & forms]
  `(binding [*lock-id* (or *lock-id* (gensym))]
     (let [lock# ~lock
           r# (Random.)]
       (loop []
         (if (= *lock-id* (deref lock#))
           (let [result# (try ~@forms
                              (catch Throwable e# e#))]
             (if (instance? Throwable result#)
               (throw result#)
               result#))
           (if (compare-and-set! lock# nil *lock-id*)
             (let [result# (try ~@forms
                                (catch Exception e# e#))]
               (reset! lock# nil)
               (if (instance? Exception result#)
                 (throw result#)
                 result#))
             (do
               ; it would be nice if there was a 'yield' -- is a random sleep here worthwhile?
               (async/<! (async/timeout (.nextInt r# 100)))
               (recur))))))))

(deftype TlsAsyncSocket [^AsynchronousSocketChannel socket ^SSLEngine engine allocator lock ^List hs-app-data began-handshake]
  nio/AsyncRead
  (read [this opts]
    (async/go
      (async-locking lock
        (let [hs-result (async/<! (-handshake this))]
          (if (s/valid? ::anomalies/anomaly hs-result)
            hs-result
            (if (.isEmpty hs-app-data)
              (let [in-buffer (async/<! (nio/allocate! allocator (.getPacketBufferSize (.getSession engine))))
                    out-buffer (async/<! (nio/allocate! allocator (.getApplicationBufferSize (.getSession engine))))
                    read (async/<! (read-tls-record socket in-buffer))]
                (if (s/valid? ::anomalies/anomaly read)
                  read
                  (let [result (.unwrap engine in-buffer out-buffer)]
                    (case (.getStatus result)
                      SSLEngineResult$Status/OK
                      (let [buffer (or (:buffer opts) (ByteBuffer/allocate (:length opts 1024)))
                            len (min (.remaining buffer) (.remaining out-buffer))]
                        (.put buffer (.limit (.slice out-buffer) len))
                        (when (.hasRemaining out-buffer)
                          (.add hs-app-data out-buffer))
                        (.bytesProduced result))

                      SSLEngineResult$Status/CLOSED
                      {::anomalies/category ::anomalies/interrupted
                       ::anomalies/message "TLS socket is closed"}

                      (SSLEngineResult$Status/BUFFER_UNDERFLOW SSLEngineResult$Status/BUFFER_OVERFLOW)
                      {::anomalies/category ::anomalies/fault
                       ::anomalies/message (str "unexpected error " (.getStatus result))}))))
              (let [buffer (or (:buffer opts) (ByteBuffer/allocate (:length opts 1024)))]
                (loop [total 0]
                  (if-let [app-buffer (first hs-app-data)]
                    (let [count (Math/min (.remaining buffer) (.remaining app-buffer))]
                      (.put buffer (-> app-buffer (.slice) (.limit count)))
                      (when (zero? (.remaining app-buffer))
                        (.remove hs-app-data 0)
                        (nio/release! allocator app-buffer))
                      (if (pos? (.remaining buffer))
                        (recur (+ total count))
                        (+ total count)))
                    total)))))))))

  nio/AsyncWrite
  (write [this buffer opts]
    (async/go
      (async-locking lock
        (let [hs-result (-handshake this)]
          (if (s/valid? ::anomalies/anomaly hs-result)
            hs-result
            (let [out-buffer (nio/allocate! allocator (.getPacketBufferSize (.getSession engine)))
                  wrap-result (.wrap engine buffer out-buffer)]
              (.flip out-buffer)
              (case (.getStatus wrap-result)
                SSLEngineResult$Status/OK
                (let [written (async/<! (nio/write socket out-buffer {}))])
;todo
                SSLEngineResult$Status/CLOSED)))))))

  Handshake
  (-handshake [this]
    (async/go-loop [in-buffer nil]
      (async-locking lock
        (case (.getHandshakeStatus engine)
          SSLEngineResult$HandshakeStatus/NOT_HANDSHAKING
          (if @began-handshake
            true
            ; for a brand new SSLEngine, begin the handshake
            (if (.getUseClientMode engine)
              ; clients begin by sending CLIENT_HELLO
              (let [buffer (async/<! (nio/allocate! allocator (.getPacketBufferSize (.getSession engine))))
                    result (.wrap engine (ByteBuffer/allocate 0) buffer)]
                (case (.getStatus result)
                  SSLEngineResult$Status/OK
                  (let [written (async/<! (write-tls-record socket (.flip buffer)))]
                    (nio/release! allocator buffer)
                    (if (s/valid? ::anomalies/anomaly written)
                      written
                      (recur nil)))

                  SSLEngineResult$Status/CLOSED
                  {::anomalies/category ::anomalies/interrupted
                   ::anomalies/message "SSLEngine closed"}

                  (SSLEngineResult$Status/BUFFER_UNDERFLOW SSLEngineResult$Status/BUFFER_OVERFLOW)
                  {::anomalies/category ::anomalies/fault
                   ::anomalies/message (str (.getStatus result))}))
              ; servers begin by receiving CLIENT_HELLO
              (let [in-buffer ])))

          SSLEngineResult$HandshakeStatus/FINISHED ; this value not ever returned here
          true

          SSLEngineResult$HandshakeStatus/NEED_TASK
          (let [task-result (async/<!
                              (async/thread
                                (let [task (.getDelegatedTask engine)]
                                  (try
                                    (.run task)
                                    (catch Exception e
                                      {::anomalies/category ::anomalies/fault
                                       ::anomalies/message (.getMessage e)
                                       :cause e})))))]
            (async/put! lock true)
            (if (s/valid? ::anomalies/anomaly task-result)
              task-result
              (recur)))

          SSLEngineResult$HandshakeStatus/NEED_UNWRAP
          (let [buffer (async/<! (nio/allocate! allocator (.getPacketBufferSize (.getSession engine))))
                read (async/<! (read-tls-record socket buffer))
                app-buffer (async/<! (nio/allocate! allocator (.getApplicationBufferSize (.getSession engine))))]
            (nio/release! allocator buffer)
            (if (s/valid? ::anomalies/anomaly read)
              read
              (let [result (.unwrap engine buffer app-buffer)]
                (case (.getStatus result)
                  SSLEngineResult$Status/OK
                  (do
                    (.add hs-app-data app-buffer)
                    (recur))

                  SSLEngineResult$Status/CLOSED
                  {::anomalies/category ::anomalies/interrupted
                   ::anomalies/message "Closed during TLS handshake"}

                  (SSLEngineResult$Status/BUFFER_OVERFLOW SSLEngineResult$Status/BUFFER_UNDERFLOW)
                  {::anomalies/category ::anomalies/fault
                   ::anomalies/message (str (.getStatus result))}))))

          SSLEngineResult$HandshakeStatus/NEED_UNWRAP_AGAIN
          "TODO"

          SSLEngineResult$HandshakeStatus/NEED_WRAP
          (let [out-buffer (nio/allocate! allocator (.getPacketBufferSize (.getSession engine)))
                result (.wrap engine (ByteBuffer/allocate 0) out-buffer)]
            (case (.getStatus result)
              SSLEngineResult$Status/OK
              (let [written (async/<! (write-tls-record socket out-buffer))]
                (if (s/valid? ::anomalies/anomaly written)
                  written
                  (recur)))

              SSLEngineResult$Status/CLOSED
              {::anomalies/category ::anomalies/interrupted
               ::anomalies/message "Socket closed during handshake."}

              (SSLEngineResult$Status/BUFFER_OVERFLOW SSLEngineResult$Status/BUFFER_UNDERFLOW)
              {::anomalies/category ::anomalies/incorrect
               ::anomalies/message (str (.getStatus result))})))))))

(defn tls-socket
  "Wrap an AsynchronousSocketChannel socket for TLS communication
  via SSLEngine engine.

  It is assumed that the socket is connected and that the engine
  is prepared for the type of communication (e.g. client, server)."
  [socket engine]
  (->TlsAsyncSocket socket engine (nio/default-allocator) (atom nil) (LinkedList.)))