package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/aixoio/aixoio-privacy-tools/lib/rsahelper"
	"github.com/google/uuid"
)

func render_folder_pk_decrypt(w fyne.Window) fyne.CanvasObject {

	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_files(w)) })
	path := ""
	path_wid := widget.NewLabel(path)
	folder_path := ""
	folder_path_wid := widget.NewLabel(path)
	path_key := ""
	path_wid_key := widget.NewLabel(path_key)
	opts := []string{"PGP", "RSA"}
	sel_wid := widget.NewSelect(opts, func(s string) {})
	sel_wid.SetSelectedIndex(0)

	actbtn := widget.NewButton("Decrypt", func() {
		file_dat, err := os.ReadFile(path)
		if err != nil {
			show_err(w)
			return
		}

		pk_file_dat, err := os.ReadFile(path_key)
		if err != nil {
			show_err(w)
			return
		}

		switch sel_wid.SelectedIndex() {
		case 0: // PGP
			var wg sync.WaitGroup

			wg.Add(1)

			var gerr error = nil

			go func() {
				defer wg.Done()
				out, err := helper.DecryptBinaryMessageArmored(string(pk_file_dat), PGP_PASSWORD, string(file_dat))
				if err != nil {
					gerr = err
					return
				}

				tmpZipFile, err := os.CreateTemp("", "apitgpgfolderzip"+uuid.NewString())
				if err != nil {
					gerr = err
					return
				}
				defer tmpZipFile.Close()
				defer os.Remove(tmpZipFile.Name())

				_, err = tmpZipFile.Write(out)
				if err != nil {
					gerr = err
					return
				}

				archive, err := zip.OpenReader(tmpZipFile.Name())
				if err != nil {
					gerr = err
					return
				}
				defer archive.Close()

				// add the name of the file to the folder
				saveFolderPath := filepath.Join(folder_path, strings.Replace(filepath.Base(path), ".zip.gpg", "", 1)+"-decrypted")
				err = os.Mkdir(saveFolderPath, os.ModePerm)
				if err != nil {
					fmt.Println(err)
					gerr = err
					return
				}

				for _, f := range archive.File {
					filePath := filepath.Join(saveFolderPath, f.Name)

					if !strings.HasPrefix(filePath, filepath.Clean(saveFolderPath)+string(os.PathSeparator)) {
						gerr = fmt.Errorf("%s: illegal file path", filePath)
						return
					}

					if f.FileInfo().IsDir() {
						os.MkdirAll(filePath, os.ModePerm)
						continue
					}

					if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
						gerr = err
						return
					}

					dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
					if err != nil {
						gerr = err
						return
					}
					defer dstFile.Close()

					fileInArachive, err := f.Open()
					if err != nil {
						gerr = err
						return
					}
					defer fileInArachive.Close()

					if _, err := io.Copy(dstFile, fileInArachive); err != nil {
						gerr = err
						return
					}

				}
			}()

			d := dialog.NewCustomWithoutButtons("Decrypting - "+path_wid.Text, container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()

			wg.Wait()

			d.Hide()

			if gerr != nil {
				show_err(w)
				return
			}

			dialog.ShowInformation("Folder decrypted", "The folder was decrypted", w)
		case 1: // RSA
			var wg sync.WaitGroup

			wg.Add(1)

			pk_key, err := rsahelper.ExportPEMStrToPrivKey(pk_file_dat)
			if err != nil {
				show_err(w)
				return
			}

			var gerr error = nil

			go func() {
				defer wg.Done()
				out, err := rsahelper.RsaDecrypt(pk_key, file_dat)
				if err != nil {
					gerr = err
					return
				}

				tmpZipFile, err := os.CreateTemp("", "apitgpgfolderzip"+uuid.NewString())
				if err != nil {
					gerr = err
					return
				}
				defer tmpZipFile.Close()
				defer os.Remove(tmpZipFile.Name())

				_, err = tmpZipFile.Write(out)
				if err != nil {
					gerr = err
					return
				}

				archive, err := zip.OpenReader(tmpZipFile.Name())
				if err != nil {
					gerr = err
					return
				}
				defer archive.Close()

				// add the name of the file to the folder
				saveFolderPath := filepath.Join(folder_path, strings.Replace(filepath.Base(path), ".afrsa", "", 1)+"-decrypted")
				err = os.Mkdir(saveFolderPath, os.ModePerm)
				if err != nil {
					fmt.Println(err)
					gerr = err
					return
				}

				for _, f := range archive.File {
					filePath := filepath.Join(saveFolderPath, f.Name)

					if !strings.HasPrefix(filePath, filepath.Clean(saveFolderPath)+string(os.PathSeparator)) {
						gerr = fmt.Errorf("%s: illegal file path", filePath)
						return
					}

					if f.FileInfo().IsDir() {
						os.MkdirAll(filePath, os.ModePerm)
						continue
					}

					if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
						gerr = err
						return
					}

					dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
					if err != nil {
						gerr = err
						return
					}
					defer dstFile.Close()

					fileInArachive, err := f.Open()
					if err != nil {
						gerr = err
						return
					}
					defer fileInArachive.Close()

					if _, err := io.Copy(dstFile, fileInArachive); err != nil {
						gerr = err
						return
					}

				}
			}()

			d := dialog.NewCustomWithoutButtons("Decrypting - "+path_wid.Text, container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()

			wg.Wait()

			d.Hide()

			if gerr != nil {
				show_err(w)
				return
			}

			dialog.ShowInformation("Folder decrypted", "The folder was decrypted", w)

		}

	})
	actbtn.Disable()

	return container.NewBorder(
		container.NewGridWithColumns(
			3,
			backbtn,
			widget.NewLabel("Folders - Public key - Decrypt"),
			widget.NewLabel(""),
		),
		actbtn,
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
							if path_key != "" && path != "" {
								actbtn.Enable()
							} else {
								actbtn.Disable()
							}
						}, w)
					}),
				),
				widget.NewLabel("Folder"),
				container.NewGridWithColumns(
					2,
					folder_path_wid,
					widget.NewButton("Select folder", func() {
						dialog.ShowFolderOpen(func(uc fyne.ListableURI, err error) {
							if uc == nil {
								return
							}
							if err != nil {
								show_err(w)
								return
							}

							folder_path = uc.Path()
							folder_path_wid.SetText(uc.Name())
							if path_key != "" && path != "" {
								actbtn.Enable()
							} else {
								actbtn.Disable()
							}
						}, w)
					}),
				),
				widget.NewLabel("Private key"),
				container.NewGridWithColumns(
					2,
					path_wid_key,
					widget.NewButton("Select file", func() {
						dialog.ShowFileOpen(func(uc fyne.URIReadCloser, err error) {
							if uc == nil {
								return
							}
							if err != nil {
								show_err(w)
								return
							}

							path_key = uc.URI().Path()
							path_wid_key.SetText(uc.URI().Name())
							if path_key != "" && path != "" {
								actbtn.Enable()
							} else {
								actbtn.Disable()
							}
						}, w)
					}),
				),
				widget.NewLabel("Cipher"),
				sel_wid,
			),
		),
	)
}
