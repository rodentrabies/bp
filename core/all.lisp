;;; Copyright (c) 2019-2023 BP Developers & Contributors
;;; See the accompanying file LICENSE for the full license governing this code.

(uiop:define-package :bp.core (:nicknames :bp :bp/core/all)
  (:use :cl)
  (:use-reexport
   :bp.core.block
   :bp.core.chain
   :bp.core.consensus
   :bp.core.encoding
   :bp.core.merkletree
   :bp.core.parameters
   :bp.core.script
   :bp.core.transaction)
  ;; For backward compatibility purposes (see rpc/all.lisp).
  (:export #:node-connection))
