package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func render_home(w fyne.Window) fyne.CanvasObject {
	return container.NewBorder(
		widget.NewLabel("aixoio's privacy tools"),
		nil,
		nil,
		nil,
		nil,
	)
}
