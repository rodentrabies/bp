(uiop:define-package :bp/core/merkletree (:use :cl)
  (:use :bp/core/encoding
        :bp/core/transaction
        :bp/crypto/hash)
  (:export
   #:build-merkle-tree
   #:merkle-tree-node
   #:merkle-tree-node-hash))

(in-package :bp/core/merkletree)

(defstruct merkle-tree-node
  hash
  left
  right)

(defun build-merkle-tree (leaves)
  "Build merkle tree from the list of transactions LEAVES by taking a
current tree level (starting from LEAVES), completing it to the even
number of elements, grouping it into pairs and constructing the next
level until it has length 1. Return a resulting root node."
  (flet ((leaf-from-tx (tx)
           (make-merkle-tree-node :hash (tx-hash tx) :left nil :right nil))
         (parent (left right)
           (let ((left-hash  (merkle-tree-node-hash left))
                 (right-hash (merkle-tree-node-hash right)))
             (make-merkle-tree-node
              :hash (hash256
                     (ironclad:with-octet-output-stream (stream)
                       (write-bytes left-hash  stream (length left-hash))
                       (write-bytes right-hash stream (length right-hash))))
              :left left
              :right right))))
    (loop
       :with next-layer := nil
       :for current-layer
         := (mapcar #'leaf-from-tx leaves) :then (reverse next-layer)
       :while (> (length current-layer) 1)
       :do
         (setf next-layer nil)
         (loop
            :for (left . (right-or-nil . nil)) :on current-layer :by #'cddr
            :for right := (or right-or-nil left)
            :do
              (push (parent left right) next-layer))
       :finally (return (first current-layer)))))
