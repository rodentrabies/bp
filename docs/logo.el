;; -*- lexical-binding: t -*-
;; Usage: load this file and call the `bp-logo' function.
;;
;; 'Leg' is the small rectangle on the top of 'b' or on the bottom of 'p'.
;; 'Body' is the big rectangle in the 'o' part of 'b' and 'p'.

(cl-defun bp-logo (&key (file "logo.svg") (fill-color "black") bg-color
                     (spacing 30)
                     (h-margin 41)
                     ;; Left paren top left x-coordinate.
                     (x-left-paren 240)
                     ;; Horizontal distance to the control point of the cubic
                     ;; Bezier curve used to draw parens. Bigger number = more
                     ;; curve to the paren.
                     (paren-control-distance 240)
                     (w-paren 173)
                     (h-paren 418)
                     (w-leg 199)
                     (h-leg 106)
                     (w-body 401)
                     (h-body 418)
                     ;; Horizontal radius of the elliptic part of 'b' and 'p'.
                     (rx-letter 154))
  (let* ((y-body (+ h-margin h-leg))
         ;; Calculate x-coordinates of entities and logo size.
         (x-b (+ x-left-paren w-paren spacing))
         (x-p (+ x-b w-body rx-letter spacing))
         (x-right-paren (+ x-p w-body rx-letter spacing))
         (w-logo (+ x-right-paren w-paren paren-control-distance))
         (h-logo (+ (* 2 h-margin) (* 2 h-leg) h-body))
         (logo (svg-create w-logo h-logo :stroke "none" :stroke-opacity 0
                           ;;:background "white"
                           )))
    (when bg-color (svg-rectangle logo 0 0 w-logo h-logo :fill bg-color))

    (cl-labels ((%paren (x-left &optional rightp)
                  (let* ((y-bottom (+ y-body h-paren))
                         (x-right (+ x-left w-paren))
                         (op (if rightp #'+ #'-))
                         (x-left-control (funcall op x-left paren-control-distance))
                         (x-right-control (funcall op x-right paren-control-distance))
                         (y-control (+ y-body (/ h-paren 2))))
                    (svg-path logo
                              `((moveto ((,x-left . ,y-body)))
                                (smooth-curveto ((,x-left-control ,y-control ,x-left ,y-bottom)))
                                (horizontal-lineto (,x-right))
                                (smooth-curveto ((,x-right-control ,y-control ,x-right ,y-body)))
                                (closepath))
                              :fill fill-color)))
                (%letter (x-body &optional bottomp)
                  (let* ((y-leg (if bottomp
                                    (1- (+ y-body h-body))
                                  (1+ (- y-body h-leg))))
                         (y-ellipse (+ y-body (/ h-body 2)))
                         (y-radius (/ h-body 2)))
                    (svg-rectangle logo x-body y-body w-body h-body :fill fill-color)
                    (svg-rectangle logo x-body y-leg w-leg h-leg :fill fill-color)
                    (svg-ellipse logo (+ x-body w-body) y-ellipse rx-letter y-radius :fill fill-color))))
      ;; Left paren.
      (%paren x-left-paren)
      ;; Letter 'b'.
      (%letter x-b)
      ;; Letter 'p'.
      (%letter x-p t)
      ;; Right paren.
      (%paren x-right-paren t)

      (when file
        (with-current-buffer (find-file-noselect file t t)
          (let ((inhibit-read-only t)
                (revert-without-query ".*"))
            (fundamental-mode)
            (set-buffer-multibyte nil)
            (erase-buffer)
            (svg-print logo)
            (save-buffer))))
      ;; DEBUG:
      ;;(with-current-buffer (get-buffer-create "*svg*")
      ;;  (erase-buffer)
      ;;  (svg-insert-image logo))
      )))

;; (bp-logo :fill-color "black" :file "logo.svg")
