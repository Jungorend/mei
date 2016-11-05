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









(print-hexstring filename (global-header :ethernet))
