;;; Copyright (c) 2019-2023 BP Developers & Contributors
;;; See the accompanying file LICENSE for the full license governing this code.

(uiop:define-package :bp.tests (:nicknames :bp/tests/all)
  (:use :cl)
  (:use
   :bp.tests.encoding
   :bp.tests.crypto
   :bp.tests.block
   :bp.tests.transaction
   :bp.tests.script))
