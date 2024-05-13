package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
)

func show_err(w fyne.Window) {
	dialog.ShowInformation("Error", "There was an error", w)
}
