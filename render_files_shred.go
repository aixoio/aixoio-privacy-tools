package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func render_files_shred(w fyne.Window) fyne.CanvasObject {
	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_files(w)) })
	path := ""
	path_wid := widget.NewLabel(path)

	boundDelTimes := binding.NewFloat()
	boundDelTimes.Set(8.0)

	delTimesSilder := widget.NewSliderWithData(1.0, 20.0, boundDelTimes)

	delbtn := widget.NewButton("Secure Delete", func() {
		file_dat, err := os.ReadFile(path)
		if err != nil {
			show_err(w)
			return
		}

		var wg sync.WaitGroup
		// var safeToDeleteMutex = sync.Mutex{}
		safeToDelete := false

		wg.Add(1)

		dialog.ShowConfirm("Secure delete", "Are you sure you want to securely delete this file?", func(b bool) {
			dialog.ShowInformation("Secure delete", fmt.Sprintf("Safe to delete: %t", b), w)
		}, w)

		wg.Wait()

		if !safeToDelete {
			dialog.ShowInformation("Secure delete", "Operation cancelled", w)
			return
		}

		wg.Add(1)

		barProgess := binding.NewFloat()
		barProgess.Set(0)

		delTimes, err := boundDelTimes.Get()
		if err != nil {
			show_err(w)
			return
		}
		totalPasses := delTimes + 1

		go func() {
			defer wg.Done()

			passesDone := 0
			barProgess.Set(float64(passesDone) / float64(totalPasses))

			random_data := make([]byte, len(file_dat))

			for i := 0; i < int(delTimes); i++ {
				if i%2 == 0 {
					_, err := rand.Read(random_data)
					if err != nil {
						show_err(w)
						return
					}
				} else {
					for j, v := range random_data {
						random_data[j] = ^v
					}
				}

				err = os.WriteFile(path, random_data, 0644)
				if err != nil {
					show_err(w)
					return
				}

				passesDone++
				barProgess.Set(float64(passesDone) / float64(totalPasses))

			}

			passesDone++
			barProgess.Set(float64(passesDone) / float64(totalPasses))

			file_dat = make([]byte, len(file_dat))

			err = os.Remove(path)
			if err != nil {
				show_err(w)
				return
			}
		}()

		d := dialog.NewCustomWithoutButtons("Deleting",
			container.NewPadded(
				widget.NewProgressBarWithData(barProgess),
			), w)

		d.Show()

		wg.Wait()

		d.Hide()

		done := dialog.NewInformation("File deleted", "The file was securely deleted", w)

		done.Show()

	})

	return container.NewBorder(
		container.NewGridWithColumns(
			3,
			backbtn,
			widget.NewLabel("File shredding (secure delete)"),
			widget.NewLabel(""),
		),
		delbtn,
		nil,
		nil,
		container.NewPadded(
			container.New(
				layout.NewFormLayout(),
				widget.NewLabel("File"),
				container.NewGridWithColumns(
					2,
					path_wid,
					widget.NewButton("Select file", func() {
						dialog.ShowFileOpen(func(uc fyne.URIReadCloser, err error) {
							if uc == nil {
								return
							}
							if err != nil {
								show_err(w)
								return
							}

							path = uc.URI().Path()
							path_wid.SetText(uc.URI().Name())
						}, w)
					}),
				),
				widget.NewLabel("Number of deletion passes"),
				container.NewGridWithColumns(
					3,
					delTimesSilder,
					widget.NewLabel("Passes:"),
					widget.NewLabelWithData(binding.FloatToStringWithFormat(boundDelTimes, "%.0f")),
				),
			),
		),
	)
}
