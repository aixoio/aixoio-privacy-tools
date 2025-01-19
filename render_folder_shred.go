package main

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func render_folder_shred(w fyne.Window) fyne.CanvasObject {
	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_files(w)) })
	path := ""
	path_wid := widget.NewLabel(path)

	boundDelTimes := binding.NewFloat()
	boundDelTimes.Set(8.0)

	delTimesSilder := widget.NewSliderWithData(1.0, 20.0, boundDelTimes)

	delbtn := widget.NewButton("Secure Delete", func() {
		var wg sync.WaitGroup
		var safeToDeleteMutex = sync.Mutex{}
		safeToDelete := false

		wg.Add(1)

		go func() {
			dialog.ShowConfirm("Secure delete", "Are you sure you want to securely delete this folder?", func(b bool) {
				safeToDeleteMutex.Lock()
				safeToDelete = b
				safeToDeleteMutex.Unlock()
				wg.Done()
			}, w)
		}()

		go func() {
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

			var totalFiles int
			err = filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() {
					totalFiles++
				}
				return nil
			})
			if err != nil {
				show_err(w)
				return
			}

			go func() {
				defer wg.Done()

				passesDone := 0
				barProgess.Set(float64(passesDone) / (totalPasses * float64(totalFiles)))

				err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}

					if !info.IsDir() {
						file_dat, err := os.ReadFile(filePath)
						if err != nil {
							return err
						}

						random_data := make([]byte, len(file_dat))

						for i := 0; i < int(delTimes); i++ {
							if i%2 == 0 {
								_, err := rand.Read(random_data)
								if err != nil {
									return err
								}
							} else {
								for j, v := range random_data {
									random_data[j] = ^v
								}
							}

							err = os.WriteFile(filePath, random_data, 0644)
							if err != nil {
								return err
							}

							passesDone++
							barProgess.Set(float64(passesDone) / (totalPasses * float64(totalFiles)))
						}

						file_dat = make([]byte, len(file_dat))
					}

					return nil
				})

				if err != nil {
					show_err(w)
					return
				}

				err = os.RemoveAll(path)
				if err != nil {
					show_err(w)
					return
				}

				passesDone++
				barProgess.Set(float64(passesDone) / (totalPasses * float64(totalFiles)))
			}()

			d := dialog.NewCustomWithoutButtons("Deleting",
				container.NewPadded(
					widget.NewProgressBarWithData(barProgess),
				), w)

			d.Show()

			wg.Wait()

			d.Hide()

			done := dialog.NewInformation("Folder deleted", "The Folder was securely deleted", w)

			done.Show()
		}()

	})

	return container.NewBorder(
		container.NewGridWithColumns(
			3,
			backbtn,
			widget.NewLabel("Folder shredding (secure delete)"),
			widget.NewLabel(""),
		),
		delbtn,
		nil,
		nil,
		container.NewVScroll(
			container.NewPadded(
				container.New(
					layout.NewFormLayout(),
					widget.NewLabel("Folder"),
					container.NewGridWithColumns(
						2,
						path_wid,
						widget.NewButton("Select folder", func() {
							dialog.ShowFolderOpen(func(uc fyne.ListableURI, err error) {
								if uc == nil {
									return
								}
								if err != nil {
									show_err(w)
									return
								}

								path = uc.Path()
								path_wid.SetText(uc.Name())
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
		),
	)
}
