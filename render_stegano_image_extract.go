package main

import (
	"bytes"
	"fmt"
	"image"
	"log"
	"os"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/scott-mescudi/stegano"
	"github.com/scott-mescudi/stegano/compression"
)

func render_stegano_image_extract(w fyne.Window) fyne.CanvasObject {
	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_steganography(w)) })

	path := ""
	path_wid := widget.NewLabel(path)
	path_bind := binding.NewString()
	path_bind.Set(path)

	bitDepth := binding.NewFloat()
	bitDepth.Set(float64(stegano.LSB))

	conc := binding.NewFloat()
	conc.Set(0)

	encON := binding.NewBool()
	encON.Set(false)

	encPwdWid := widget.NewPasswordEntry()

	encCon := container.New(
		layout.NewFormLayout(),
		widget.NewLabel("Password"),
		encPwdWid,
	)

	actbtn := widget.NewButton("Extract", func() {
		coverDat, err := os.ReadFile(path)
		if err != nil {
			show_err(w)
			return
		}

		img, _, err := image.Decode(bytes.NewReader(coverDat))
		if err != nil {
			show_err(w)
			return
		}

		var extacter *stegano.ExtractHandler

		concVal, err := conc.Get()
		if err != nil {
			show_err(w)
			return
		}

		if concVal == 0 {
			extacter = stegano.NewExtractHandler()
		} else {
			extacter, err = stegano.NewExtractHandlerWithConcurrency(int(concVal))
			if err != nil {
				show_err(w)
				return
			}
		}

		bitDepthFloat, err := bitDepth.Get()
		if err != nil {
			show_err(w)
			return
		}
		bitDepthUint8 := uint8(bitDepthFloat)

		datc := make(chan []byte, 1)

		var wg sync.WaitGroup
		wg.Add(1)

		var gerr error = nil

		go func(gerrp *error) {
			defer wg.Done()

			eon, err := encON.Get()
			if err != nil {
				fmt.Println(gerr, 1)
				gerr = err
				return
			}

			dataDat, err := extacter.ExtractAtDepth(img, bitDepthUint8)
			if err != nil {
				gerr = err
				fmt.Println(gerr, 4)
				return
			}

			dataDat, err = compression.DecompressZSTD(dataDat)
			if err != nil {
				gerr = err
				fmt.Println(gerr, 3)
				return
			}

			if eon {
				dataDat, err = stegano.DecryptData(dataDat, encPwdWid.Text)
				if err != nil {
					gerr = err
					fmt.Println(gerr, 2)
					return
				}
			}

			datc <- dataDat

		}(&gerr)

		d := dialog.NewCustomWithoutButtons("Extracting - "+path_wid.Text, container.NewPadded(
			widget.NewProgressBarInfinite(),
		), w)

		d.Show()

		wg.Wait()

		d.Hide()

		if gerr != nil {
			dialog.ShowError(gerr, w)
			fmt.Println("GOT", gerr, 5)
			return
		}

		fd := dialog.NewFileSave(func(uc fyne.URIWriteCloser, err error) {
			if uc == nil {
				return
			}
			if err != nil {
				show_err(w)
				return
			}

			_, err = uc.Write(<-datc)
			if err != nil {
				show_err(w)
				return
			}
			uc.Close()
		}, w)
		fd.Show()

	})
	actbtn.Disable()

	encON.AddListener(binding.NewDataListener(func() {
		enc, err := encON.Get()
		if err != nil {
			log.Printf("Error getting encryption status: %v", err)
			return
		}
		if enc {
			encCon.Show()
		} else {
			encCon.Hide()
		}
	}))

	return container.NewBorder(
		container.NewGridWithColumns(
			3,
			backbtn,
			widget.NewLabel("Steganography - Images"),
			widget.NewLabel(""),
		),
		actbtn,
		nil,
		nil,
		container.NewPadded(
			container.New(
				layout.NewFormLayout(),
				widget.NewLabel("Image"),
				container.NewGridWithColumns(
					2,
					path_wid,
					widget.NewButton("Select file", func() {
						fd := dialog.NewFileOpen(func(uc fyne.URIReadCloser, err error) {
							if uc == nil {
								return
							}
							if err != nil {
								show_err(w)
								return
							}

							path = uc.URI().Path()
							path_wid.SetText(uc.URI().Name())
							path_bind.Set(path)
							if path != "" {
								actbtn.Enable()
							} else {
								actbtn.Disable()
							}
						}, w)
						fd.SetFilter(storage.NewExtensionFileFilter([]string{".png", ".jpg", ".jpeg", "gif"}))
						fd.Show()
					}),
				),
				widget.NewLabel("Bit depth"),
				container.NewGridWithColumns(
					2,
					widget.NewSliderWithData(float64(stegano.LSB), float64(stegano.MaxBitDepth), bitDepth),
					widget.NewLabelWithData(binding.NewSprintf("%.0f", bitDepth)),
				),
				widget.NewLabel("Concurrency"),
				container.NewGridWithColumns(
					3,
					widget.NewSliderWithData(0, 24, conc),
					widget.NewLabelWithData(binding.NewSprintf("%.0f", conc)),
					widget.NewLabel("0: single-threaded"),
				),
				widget.NewLabel("Encryption"),
				widget.NewCheckWithData("", encON),
				container.NewCenter(),
				encCon,
			),
		),
	)
}
