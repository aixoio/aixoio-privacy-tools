package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
)

func main() {

	a := app.New()
	w := a.NewWindow("aixoio's privacy tools")

	w.Resize(fyne.NewSize(float32(WIDTH), float32(HEIGHT)))

	w.ShowAndRun()

}
