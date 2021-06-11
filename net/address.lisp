(uiop:define-package :bp/net/address (:use :cl)
  (:use :bp/core/encoding)
  (:import-from :usocket)
  (:export
   ;; Address utilities:
   #:split-host/port-string
   #:address-to-bytes
   #:address-from-bytes
   #:random-peer-address))

(in-package :bp/net/address)

;;; Address management and peer-discovery utilities.

(defun split-host/port-string (string)
  (let ((position (position #\: string :test #'char=)))
    (if position
        (values (subseq string 0 position)
                (parse-integer string :start (1+ position)))
        (values string nil))))

;; NOTE: currently only supports IPv4 addresses.
(defun address-to-bytes (address)
  (let ((bytes (make-byte-array 16)))
    ;; IPv4-mapped IPv6 address.
    (setf (aref bytes 10) #xff)
    (setf (aref bytes 11) #xff)
    (usocket:ip-to-octet-buffer address bytes :start 12)
    bytes))

;; NOTE: currently only supports IPv4 addresses.
(defun address-from-bytes (bytes)
  ;; (assert (and (= (aref bytes 10) #xff) (= (aref bytes 11) #xff)) ()
  ;;         "Currently IPv4 addresses are supported.")
  (usocket:hbo-to-dotted-quad (usocket:ip-from-octet-buffer bytes :start 12)))

(defvar *dns-seed* '("seed.bitcoin.sipa.be")
  "DNS seed is a list of hardcoded host names for Bitcoin nodes that
can accept new connections when bootstrapping new nodes.")

(defun random-peer-address ()
  (flet ((randelt (lst) (nth (random (length lst)) lst)))
    (randelt
     ;; NOTE: currently only supports IPv4 address, hence the filtering.
     (mapcar
      (lambda (addr) (usocket:hbo-to-dotted-quad (usocket:ip-from-octet-buffer addr)))
      (remove-if-not
       (lambda (addr) (= (length addr) 4))
       (usocket:get-hosts-by-name (randelt *dns-seed*)))))))
