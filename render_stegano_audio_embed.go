package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/aixoio/aixoio-privacy-tools/lib/aes"
	"github.com/aixoio/aixoio-privacy-tools/lib/hashing"
	"github.com/google/uuid"
	"github.com/scott-mescudi/stegano"
	"github.com/scott-mescudi/stegano/compression"
)

func render_stegano_audio_embed(w fyne.Window) fyne.CanvasObject {
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

	encON := binding.NewBool()
	encON.Set(false)

	encPwdWid := widget.NewPasswordEntry()

	encCon := container.New(
		layout.NewFormLayout(),
		widget.NewLabel("Password"),
		encPwdWid,
	)

	actbtn := widget.NewButton("Embed", func() {

		dataDat, err := os.ReadFile(path_dat)
		if err != nil {
			show_err(w)
			return
		}

		var embedder *stegano.AudioEmbedHandler

		bitDepthFloat, err := bitDepth.Get()
		if err != nil {
			show_err(w)
			return
		}
		bitDepthUint8 := uint8(bitDepthFloat)

		var wg sync.WaitGroup
		wg.Add(1)

		var gerr error = nil
		datc := make(chan []byte, 1)

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
				dat, err = aes.AesGCMEncrypt(hashing.Sha256_to_bytes([]byte(encPwdWid.Text)), dataDat)
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

			dane, err := os.MkdirTemp("", "wavembedding"+uuid.NewString())
			if err != nil {
				gerr = err
				fmt.Println(gerr, 5)
				return
			}
			defer os.RemoveAll(dane)

			outFileName := filepath.Join(dane, fmt.Sprintf("%s.wav", uuid.NewString()))

			err = embedder.EmbedIntoWAVWithDepth(path, outFileName, dat, bitDepthUint8)
			if err != nil {
				gerr = err
				fmt.Println(gerr, 4)
				return
			}

			outData, err := os.ReadFile(outFileName)
			if err != nil {
				gerr = err
				fmt.Println(gerr, 6)
				return
			}

			datc <- outData

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
				show_err(w)
				return
			}

			_, err = uc.Write(<-datc)
			if err != nil {
				show_err(w)
				return
			}
			uc.Close()

			dialog.ShowInformation("File saved", "The file was saved", w)

		}, w)
		fd.SetFileName(strings.Replace(path_wid.Text, ".wav", "", 1) + " - Embedded.wav")
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
			widget.NewLabel("Steganography - Audio"),
			widget.NewLabel(""),
		),
		actbtn,
		nil,
		nil,
		container.NewPadded(
			container.New(
				layout.NewFormLayout(),
				widget.NewLabel("Cover File"),
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
							if path_dat != "" && path != "" {
								actbtn.Enable()
							} else {
								actbtn.Disable()
							}
						}, w)
						fd.SetFilter(storage.NewExtensionFileFilter([]string{".wav"}))
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
								show_err(w)
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
				widget.NewLabel("Encryption"),
				widget.NewCheckWithData("", encON),
				container.NewCenter(),
				encCon,
			),
		),
	)
}
