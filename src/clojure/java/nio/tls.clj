(ns clojure.java.nio.tls
  (:require [clojure.java.nio :as nio]
            [cognitect.anomalies :as anomalies]
            [clojure.core.async :as async]
            [clojure.spec.alpha :as s])
  (:import (javax.net.ssl SSLEngine SSLEngineResult SSLEngineResult$HandshakeStatus SSLEngineResult$Status)
           (java.nio.channels AsynchronousSocketChannel)
           (java.nio ByteBuffer)
           (java.util List Random)
           (java.util.concurrent.locks Lock)))

(defprotocol Handshake
  (-handshake [this]
    "Run the handshake. Returns a channel that yields a value when
    the handshake completes, or an anomaly on error."))

(defmacro async-locked
  [^Lock lock & forms]
  `(let [lock# ~lock
         r# (Random.)]
     (loop []
       (if (.tryLock lock#)
         (let [result# (try ~@forms
                            (catch Exception e# e#))]
           (.unlock lock#)
           (if (instance? Exception result#)
             (throw result#)
             result#))
         (do
           ; it would be nice if there was a 'yield' -- is a random sleep here worthwhile?
           (async/<! (async/timeout (.nextInt r# 100)))
           (recur))))))

(deftype TlsAsyncSocket [^AsynchronousSocketChannel socket ^SSLEngine engine allocator lock ^List hs-app-data]
  nio/AsyncRead
  (read [this opts]
    (async/go
      (async-locked lock
        (let [hs-result (async/<! (-handshake this))]
          (if (s/valid? ::anomalies/anomaly hs-result)
            hs-result
            (if (.isEmpty hs-app-data)
              (let [in-buffer (async/<! (nio/allocate! allocator (.getPacketBufferSize (.getSession engine))))
                    out-buffer (async/<! (nio/allocate! allocator (.getApplicationBufferSize (.getSession engine))))
                    read (async/<! (nio/read socket {:buffer in-buffer}))]
                (if (s/valid? ::anomalies/anomaly read)
                  read
                  (let [result (.unwrap engine in-buffer out-buffer)]
                    (case (.getStatus result)))))
              (let [buffer (or (:buffer opts) (ByteBuffer/allocate (:length opts 1024)))]
                (loop [total 0]
                  (if-let [app-buffer (first hs-app-data)]
                    (let [count (Math/min (.remaining buffer) (.remaining app-buffer))]
                      (.put buffer (-> app-buffer (.slice) (.limit count)))
                      (when (zero? (.remaining app-buffer))
                        (.remove hs-app-data 0))
                      (if (pos? (.remaining buffer))
                        (recur (+ total count))
                        (+ total count)))
                    total)))))))))

  nio/AsyncWrite
  (write [this buffer opts]
    (async-locked lock
      (comment 'todo)))

  Handshake
  (-handshake [this]
    (async/go-loop []
      (async-locked lock
        (case (.getHandshakeStatus engine)
          SSLEngineResult$HandshakeStatus/NOT_HANDSHAKING
          (do
            (async/put! lock true)
            true)

          SSLEngineResult$HandshakeStatus/FINISHED
          (do
            (async/put! lock true)
            true)

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
                read (async/<! (nio/read socket {:buffer buffer}))
                app-buffer (async/<! (nio/allocate! allocator (.getApplicationBufferSize (.getSession engine))))]
            (async/put! lock true)
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
          "TODO")))))