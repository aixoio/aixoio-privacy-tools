package main

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
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
	"github.com/dustin/go-humanize"
	"github.com/scott-mescudi/stegano"
	"github.com/scott-mescudi/stegano/compression"
)

func render_stegano_image_embed(w fyne.Window) fyne.CanvasObject {
	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_steganography(w)) })

	path := ""
	path_wid := widget.NewLabel(path)
	path_bind := binding.NewString()
	path_bind.Set(path)

	path_dat := ""
	path_dat_wid := widget.NewLabel(path_dat)
	path_dat_bind := binding.NewString()
	path_dat_bind.Set(path)

	bitDepth := binding.NewFloat()
	bitDepth.Set(float64(stegano.LSB))

	conc := binding.NewFloat()
	conc.Set(0)

	encON := binding.NewBool()
	encON.Set(false)

	encPwdWid := widget.NewPasswordEntry()

	capWid := widget.NewLabel("????")
	maxCapWid := widget.NewLabel("????")

	canFit := widget.NewLabel("Can fit: ????")

	encCon := container.New(
		layout.NewFormLayout(),
		widget.NewLabel("Password"),
		encPwdWid,
	)

	actbtn := widget.NewButton("Embed", func() {
		coverDat, err := os.ReadFile(path)
		if err != nil {
			show_err(w, err)
			return
		}

		dataDat, err := os.ReadFile(path_dat)
		if err != nil {
			show_err(w, err)
			return
		}

		img, _, err := image.Decode(bytes.NewReader(coverDat))
		if err != nil {
			show_err(w, err)
			return
		}

		var embedder *stegano.EmbedHandler

		concVal, err := conc.Get()
		if err != nil {
			show_err(w, err)
			return
		}

		if concVal == 0 {
			embedder = stegano.NewEmbedHandler()
		} else {
			embedder, err = stegano.NewEmbedHandlerWithConcurrency(int(concVal))
			if err != nil {
				show_err(w, err)
				return
			}
		}

		bitDepthFloat, err := bitDepth.Get()
		if err != nil {
			show_err(w, err)
			return
		}
		bitDepthUint8 := uint8(bitDepthFloat)

		var stegimg image.Image

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

			dat := dataDat
			if eon {
				dat, err = stegano.EncryptData(dataDat, encPwdWid.Text)
				if err != nil {
					gerr = err
					fmt.Println(gerr, 2)
					return
				}
			}

			dat, err = compression.CompressZSTD(dat)
			if err != nil {
				gerr = err
				fmt.Println(gerr, 3)
				return
			}

			stegimg, err = embedder.EmbedDataIntoImage(img, dat, bitDepthUint8)
			if err != nil {
				gerr = err
				fmt.Println(gerr, 4)
				return
			}
		}(&gerr)

		d := dialog.NewCustomWithoutButtons("Embedding - "+path_wid.Text, container.NewPadded(
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
				show_err(w, err)
				return
			}

			// save stegano image with uc
			err = png.Encode(uc, stegimg)
			if err != nil {
				show_err(w, err)
				return
			}
			uc.Close()

			dialog.ShowInformation("File saved", "The file was saved", w)

		}, w)
		fd.SetFileName(path_wid.Text + ".png")
		fd.Show()

	})
	actbtn.Disable()

	calc_bDepth := func() {
		img, err := stegano.Decodeimage(path)
		if err != nil {
			capWid.SetText("????")
			maxCapWid.SetText("????")
			canFit.SetText("Can fit: ????")
			return
		}

		bitDepthFloat, err := bitDepth.Get()
		if err != nil {
			log.Printf("Error getting bit depth: %v", err)
			capWid.SetText("????")
			maxCapWid.SetText("????")
			canFit.SetText("Can fit: ????")
			return
		}
		bitDepthUint8 := uint8(bitDepthFloat)

		currentCap := stegano.GetImageCapacity(img, bitDepthUint8)
		capWid.SetText(humanize.Bytes(uint64(currentCap)))

		maxCap := stegano.GetImageCapacity(img, stegano.MaxBitDepth)
		maxCapWid.SetText(humanize.Bytes(uint64(maxCap)))

		// get size in bytes of file at data_path
		fileInfo, err := os.Stat(path_dat)
		if err != nil {
			log.Printf("Error getting file info for %s: %v", path_dat, err)
			canFit.SetText("Can fit: ????")
			return
		}
		fileSize := fileInfo.Size()
		if fileSize > int64(currentCap) {
			canFit.SetText("Cannot fit")
		} else {
			canFit.SetText("Can fit")
		}
	}

	path_bind.AddListener(binding.NewDataListener(func() {
		go calc_bDepth()
	}))

	path_dat_bind.AddListener(binding.NewDataListener(func() {
		go calc_bDepth()
	}))

	bitDepth.AddListener(binding.NewDataListener(func() {
		go calc_bDepth()
	}))

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
				widget.NewLabel("Cover Image"),
				container.NewGridWithColumns(
					2,
					path_wid,
					widget.NewButton("Select file", func() {
						fd := dialog.NewFileOpen(func(uc fyne.URIReadCloser, err error) {
							if uc == nil {
								return
							}
							if err != nil {
								show_err(w, err)
								return
							}

							path = uc.URI().Path()
							path_wid.SetText(uc.URI().Name())
							path_bind.Set(path)
							if path_dat != "" && path != "" {
								actbtn.Enable()
							} else {
								actbtn.Disable()
							}
						}, w)
						fd.SetFilter(storage.NewExtensionFileFilter([]string{".png", ".jpg", ".jpeg"}))
						fd.Show()
					}),
				),
				widget.NewLabel("File (Embeded file)"),
				container.NewGridWithColumns(
					2,
					path_dat_wid,
					widget.NewButton("Select file", func() {
						dialog.ShowFileOpen(func(uc fyne.URIReadCloser, err error) {
							if uc == nil {
								return
							}
							if err != nil {
								show_err(w, err)
								return
							}

							path_dat = uc.URI().Path()
							path_dat_wid.SetText(uc.URI().Name())
							path_dat_bind.Set(path_dat)
							if path_dat != "" && path != "" {
								actbtn.Enable()
							} else {
								actbtn.Disable()
							}
						}, w)
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
				widget.NewLabel("Capacity:"),
				container.NewGridWithColumns(
					4,
					capWid,
					widget.NewLabel("Max Capacity:"),
					maxCapWid,
					canFit,
				),
			),
		),
	)
}
