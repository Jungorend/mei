(ns scratchpad
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

;;----

(def link-types
  {:ethernet 1
   :raw 101
   :usb_linux 189
   :ipv4 228
   :ipv6 229
   })

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
  (convert-to-hex [ts_sec 8]
                   [ts_usec 8]
                   [incl_len 8]
                   [orig_len 8]))
