(ns clojure.java.nio
  (:require [clojure.core.async :as async]
            [cognitect.anomalies :as anomalies]
            [clojure.spec.alpha :as s])
  (:import (java.nio.channels AsynchronousSocketChannel CompletionHandler AsynchronousFileChannel AsynchronousServerSocketChannel)
           (java.util.concurrent TimeUnit)
           (java.nio ByteBuffer)
           (java.net InetSocketAddress InetAddress)))

(defprotocol AsyncRead
  (read [this opts]
    "Asynchronously read bytes from a channel. Returns a promise
    channel that will yield a map containing values:

    - :length - the number of bytes read, or a negative value if
      the channel is closed.
    - :buffer - the ByteBuffer containing the bytes read.

    The channel returns an anomaly on error.

    Options map may include:

    - :length - the number of bytes to read. Specify this or buffer.
    - :buffer - a ByteBuffer to read into. Will attempt to read
      as many bytes as available in the buffer.
    - :timeout - an integer, the timeout, default 0 (no timeout).
      Only supported for network channels.
    - :timeout-units - a TimeUnit, default milliseconds.
    - :position - an integer, the position to read in file channels."))

(defprotocol AsyncWrite
  (write [this buffer opts]
    "Asynchronously write bytes to a channel. Returns a promise
    channel that will yield a map containing values:

    - :length - the number of bytes written.

    The channel returns an anomaly on error.

    Options map may include:

    - :timeout - an integer, the timeout, default 0 (no timeout).
      Only valid for network channels.
    - :timeout-units - a TimeUnit, default milliseconds"))

(defprotocol AsyncConnect
  (connect [this address opts]
    "Asynchronously connect to an address.

    Returns a promise channel that will yield an empty map
    on connect. The channel returns an anomaly on error.

    Opts is currently unused."))

(defprotocol AsyncAccept
  (accept [this opts]
    "Accept a new connection on a server socket. Returns
     a promise channel that will yield a new AsynchronousSocketChannel,
     or an anomaly on error."))

(defn- completion-handler
  [on-success on-failure]
  (reify CompletionHandler
    (completed [_ result attachment]
      (on-success result attachment))
    (failed [_ exception attachment]
      (on-failure exception attachment))))

(defn exception-handler
  [exception channel]
  ; todo translate exceptions as appropriate
  (async/put! channel {::anomalies/category ::anomalies/fault
                       ::cause exception}))

(extend-protocol AsyncRead
  AsynchronousSocketChannel
  (read [this opts]
    (let [{:keys [length buffer timeout timeout-units]
           :or   {timeout 0 timeout-units TimeUnit/MILLISECONDS}} opts
          response (async/promise-chan)]
      (if (or length buffer)
        (let [buffer (or buffer (ByteBuffer/allocate length))]
          (.read this buffer
                 timeout timeout-units
                 response
                 (completion-handler (fn [res ch] (async/put! ch {:length res :buffer buffer}))
                                     exception-handler)))
        (async/put! response {::anomalies/category ::anomalies/incorrect
                              ::anomalies/message "Must supply length or a buffer."}))
      response)))

(extend-protocol AsyncRead
  AsynchronousFileChannel
  (read [this opts]
    (let [{:keys [length buffer position]
           :or   {position 0}} opts
          response (async/promise-chan)]
      (if (or length buffer)
        (let [buffer (or buffer (ByteBuffer/allocate length))]
          (.read this buffer
                 position
                 response
                 (completion-handler (fn [res ch] (async/put! ch {:length res :buffer buffer}))
                                     exception-handler)))
        (async/put! response {::anomalies/category ::anomalies/incorrect
                              ::anomalies/message "Must supply length or a buffer."}))
      response)))

(extend-protocol AsyncWrite
  AsynchronousSocketChannel
  (write [this buffer opts]
    (let [{:keys [timeout timeout-units] :or {timeout 0 timeout-units TimeUnit/MILLISECONDS}} opts
          response (async/promise-chan)]
      (.write this buffer timeout timeout-units response
              (completion-handler (fn [res ch] (async/put! ch {:length res}))
                                  exception-handler))
      response)))

(extend-protocol AsyncConnect
  AsynchronousSocketChannel
  (connect [this address opts]
    (let [response (async/promise-chan)]
      (.connect this address response
                (completion-handler (fn [_ ch] (async/put! ch {}))
                                    exception-handler))
      response)))

(extend-protocol AsyncAccept
  AsynchronousServerSocketChannel
  (accept [this opts]
    (let [response (async/promise-chan)]
      (.accept this response
               (completion-handler (fn [chan ch] (async/put! ch chan))
                                   exception-handler))
      response)))

(defn wrap-socket
  [socket {:keys [buffer-size] :or {buffer-size 1024}}]
  (let [send (async/chan 16)
        recv (async/chan 16)]
    (async/go-loop []
      (if-let [msg (async/<! send)]
        (let [result (async/<! (write socket msg {}))]
          (if (s/valid? ::anomalies/anomaly result)
            (do
              (.close socket)
              (async/put! result recv)
              (async/close! recv)
              (async/close! send))
            (recur)))))
    (async/go-loop []
      (let [result (async/<! (read socket {:length buffer-size}))]
        (cond (s/valid? ::anomalies/anomaly result)
              (do
                (.close socket)
                (async/put! recv result)
                (async/close! recv)
                (async/close! send))
              (neg? (:length result)) (do
                                        (async/close! recv)
                                        (async/close! send))
              :else (when (async/>! recv result)
                      (recur)))))
    {:send send :recv recv :socket socket}))

(defn socket-channel
  "Create a socket channel, connect, and return a pair of
   channels for communicating with this socket.

   Returns a channel that will yield a map with keys:

   - :send - The channel to send ByteBuffers to the channel.
   - :recv - The channel to receive ByteBuffers from the channel.
   - :socket - The AsynchronousSocketChannel.

   On error, returns an anomaly.

   If an error occurs while reading or writing, and anomaly will
   be passed to the recv channel, and the channels and socket
   will be closed.

   Closing the send channel will close the socket."
  [address {:keys [buffer-size] :or {buffer-size 1024} :as opts}]
  (let [socket (AsynchronousSocketChannel/open)]
    (async/go
      (let [connect-result (async/<! (connect socket address {}))]
        (if (s/valid? ::anomalies/anomaly connect-result)
          connect-result
          (wrap-socket socket opts))))))

(defn server
  "Create a server socket channel, which will constantly accept
  connections and will pass each new connection to the function
  handler. Each connection passed will be as passed through
  wrap-socket.

  Options include:

  - :backlog - the server socket backlog, default 0.
  - :bind-address - address to bind to, defaults to localhost with a port of 0 (a random port).
  - :buffer-size - the buffer size per connection. Defaults to 1024.

  Returns a map of values:

  - :socket - The server socket channel.
  - :close-chan - A channel that, when closed, will close the server.
  - :server-chan - A channel that will close when the server channel is closed."
  [handler {:keys [backlog bind-address buffer-size]
            :or {backlog 0
                 bind-address (InetSocketAddress. (InetAddress/getLocalHost) 0)
                 buffer-size 1024}}]
  (let [channel (AsynchronousServerSocketChannel/open)
        closer (async/promise-chan)]
    (.bind channel bind-address backlog)
    (let [server-loop (async/go-loop []
                        (let [result (async/alt!
                                       (accept channel {}) ([v] v)
                                       closer :closed)]
                          (if (= result :closed)
                            (.close channel)
                            (do
                              (async/go (async/<! (handler (wrap-socket result {:buffer-size buffer-size}))))
                              (recur)))))]
      {:socket channel :close-chan closer :server-loop server-loop})))

(defprotocol Allocator
  (allocate! [this size]
    "Allocate a new ByteBuffer with capacity at least size.")

  (release! [this buffer]
    "Return a buffer to this allocator."))

(deftype DefaultAllocator [direct?]
  Allocator
  (allocate! [_ size]
    (async/go
      (if direct?
        (ByteBuffer/allocateDirect size)
        (ByteBuffer/allocate size))))

  (release! [_ _]
    (async/go))) ; no-op, managed by GC

(defn default-allocator [& {:keys [direct?]}] (->DefaultAllocator direct?))