package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
)

func show_err(w fyne.Window, err error) {
	dialog.ShowError(err, w)
}
