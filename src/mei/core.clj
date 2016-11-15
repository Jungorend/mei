(ns mei.core
  (:require [clojure.string :as str]))

(defn third [a]
  (second (rest a)))

(defn hex-string-to-int [data]
  "Takes in an input hex string and returns it as a integer list"
    (map #(Integer/parseInt % 16) (str/split (str/replace data #"(.{2})(?!$)" "$1 ") #" ")))

(defn print-hexstring [file data]
  "Appends the hexstring to a file"
  (map (fn [character]
         (with-open [w (clojure.java.io/output-stream file :append true)]
           (.write w character)))
       (hex-string-to-int data)))

(defn convert-to-hex [& values]
  "Takes a series of [data byte-size & hex?] and converts it to a hex-string
  If the third value passed in is true, the data will be passed as is, otherwise it converts it to hex first"
  (str/replace (apply str
         (map (fn [[data length & hex?]]
                (cond hex? data
                      :else (format (str "%" length "x") data))) values)) #" " "0"))

(defn text-to-hex
  "Creates the hex equivalent of a text string"
  [text]
  (apply convert-to-hex (map vector (map int text) (repeat 2))))
;;----

(def link-types
  {:ethernet 1
   :raw 101
   :usb_linux 189
   :ipv4 228
   :ipv6 229
   })

(def ether-types
  {:ipv4 "0800"
   :arp  "0806"
   :ipv6 "86DD"})

(def ip-protocols
  {:icmp "01"
   :udp "11"
   :tcp "06"})

(def timestamp (atom (rand-int 15129)))
(def source-port (atom (+ 1024 (rand-int 1000))))
(def mac-dst "aaaaaaaaaaaa")
(def mac-src "bbbbbbbbbbbb")
(def src-ip "0aaaaaaa")
(def dst-ip "0aaaaaab")
(def filename "test.pcap")

(defn global-header [link]
  "Takes a link type and produces the global header for a pcap as a string"
  (convert-to-hex
    ["a1b2c3d4" 8 true] ; Magic Number
    ["02000400" 8 true] ; Version 2.4
    ["00000000" 8 true] ; UTC timezone
    ["00000000" 8 true] ; Always 0
    ["0000ffff" 8 true] ; snaplength 65535
    [(get link-types link) 8]))

(defn record-header [ts_sec ts_usec incl_len orig_len]
  (convert-to-hex [ts_sec 8]     ; timestamp seconds
                  [ts_usec 8]    ; timestamp microseconds
                  [incl_len 8]   ; number of octets of packet saved in file
                  [orig_len 8])) ; actual length of packet

(defn create-record-header [data]
  (swap! timestamp #(+ % 1))
  (let [len (/ (count data) 2)]
    (record-header @timestamp 0 len len)))

(defn create-packet [data]
  (print-hexstring filename (str (create-record-header data) data)))

;;---------

(defn ethernet-packet [type data]
  (convert-to-hex [mac-dst 12 true]
                  [mac-src 12 true]
                  [(get ether-types type) 4 true]
                  [data 0 true]
                  ["c704dd7b" 8 true]    ;; TODO: Actual FCS checki
                  ))

(defn ipv4-packet [protocol src-ip dst-ip data]
  (convert-to-hex ["4" 1 true]
                  ["5" 1 true] ;; TODO: Maybe add IP options?
                  ["00" 2 true] ;; TODO: VoIP?
                  [(+ 20 (/ (count data) 2)) 4] ;;size of the entire packet
                  [0 4]         ;; TODO: Basically everything here
                  [0 4]
                  [15 2]
                  [(get ip-protocols protocol) 2 true]
                  [0 4] ;; TODO: More Checksums....
                  [src-ip 8 true]
                  [dst-ip 8 true]
                  [data 0 true]))



(defn udp-packet [dport data]
  (convert-to-hex [@source-port 4]
                  [dport 4]
                  [(/ (count data) 2) 4]
                  [0 4]
                  [data 0 true]))                    ;; TODO: No checksum validation yet. Will add later


;;(print-hexstring filename (global-header :ethernet))

;;----------------------Reading an existing pcap
(defn read-pcap [filename]
  "Reads a file and returns it as a hex-string"
  (let [bytes (java.nio.file.Files/readAllBytes (.toPath (java.io.File. filename)))]
    (clojure.string/replace (apply str (map (fn [byte]
                                              (let [b (int byte)]
                                                (format "%2x" (if (< b 0) (bit-and b 0xff) b)))) bytes)) " " "0")))

(defn little-endian? [string]
  (if (= "d4c3b2a1" (apply str (take 8 string)))   ;; Not yet used
    true false))

(defn reverse-endian
  "Returns the structure with all the values having reverse endian"
  [structure]
  (let [re (fn [string]
             (clojure.string/join (map (partial clojure.string/join) (reverse (partition 2 string)))))]
    (reduce (fn [results [k v]]
              (assoc results k (re (get structure k)))) structure structure)))

(defn pull-data
  "Field should be [key size]
  it will update all the provided keys in the structure with the
  size amount of data. size can be a function of the remaining data."
  [data structure fields]
  (if (empty? fields)
    [structure data]
    (let [[k size] (first fields)
          length (if (fn? size) (size data) size)]
      (recur (drop length data)
             (assoc structure k (apply str (take length data)))
             (rest fields)))))

(defrecord pcap-header [magic-number version timezone zero snaplength link-type])
(defrecord pcap-record [ts_sec ts_usec incl_len orig_len])
(defrecord ethernet    [mac-dst mac-src header-8021q ethertype]) ;; Everything after the ether-type is unnecessary to know
(defrecord ipv4        [version ihl dscp ecn total-length identification flags fragment-offset ttl protocol header-checksum
                        source-ip destination-ip options])


(defn read-global-header
  "From a packet capture, returns the global header at the beginning of a libpcap file
  as a pcap-header, and the remainder of the string in a vector."
  [string]
  (pull-data string (->pcap-header nil nil nil nil nil nil)
             [[:magic-number 8]
              [:version 8]
              [:timezone 8]
              [:zero 8]
              [:snaplength 8]
              [:link-type 8]]))

(defn read-record
  "From a packet capture without a global header, returns a pcap-record and the remainder of the
  data in a vector."
  [string]
  (pull-data string (->pcap-record nil nil nil nil)
             [[:ts_sec 8]
              [:ts_usec 8]
              [:incl_len 8]
              [:orig_len 8]]))

(defn read-ethernet
  "Takes a string and returns an ethernet record and the remainder of the data"
  [string]
  (pull-data string (->ethernet nil nil nil nil)
             [[:mac-dst 12]
              [:mac-src 12]
              [:header-8021q (fn [a] (let [field (apply str (take 4 a))]
                                      (cond (= "8100" field) 8
                                            (= "9100" field) 16
                                            :else 0)))]
              [:ethertype 4]]))

(defn packet-data
  "Takes in a string beginning at a packet data chunk, and a boolean
  telling the function whether the traffic is little endian or not.
  Returns the next packet data chunk and the remaining string from a chunk"
  [string little?]
  (let [[packet-record string] (read-record string)
        length (* 2                                                     ;; Two characters per byte
                  (Integer/parseInt (:orig_len (if little? (reverse-endian packet-record) packet-record)) 16))]
    [(apply str (take length string)) (drop length string)]))


(defn read-ipv4
  "Takes in a string and extracts the ipv4 header, then returns the remainder in a vector"
  [string]
  (pull-data string (apply (partial ->ipv4) (repeat 14 'nil))
             [[:version 1] [:ihl 1] [:dscp 2] [:total-length 4]
              [:identification 4] [:flags 4] ;; flags includes fragment offset
              [:ttl 2] [:protocol 2] [:header-checksum 4]
              [:source-ip 8]
              [:destination-ip 8]])) ;;;note, not using options yet







































;; OoO read-pcap -> read-global-header -> packet-data -> read-ethernet -> (potential check) -> read-ipv4
