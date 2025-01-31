package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"filippo.io/age"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/aixoio/aixoio-privacy-tools/lib/aes"
	"github.com/aixoio/aixoio-privacy-tools/lib/asconhelper"
	"github.com/aixoio/aixoio-privacy-tools/lib/combohelper"
	"github.com/aixoio/aixoio-privacy-tools/lib/hashing"
	"github.com/aixoio/aixoio-privacy-tools/lib/serpent"
	"github.com/aixoio/aixoio-privacy-tools/lib/twofish"
	"github.com/aixoio/aixoio-privacy-tools/lib/xchachahelper"
	"github.com/google/uuid"
)

func render_folder_decrypt(w fyne.Window) fyne.CanvasObject {

	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_files(w)) })
	path := ""
	path_wid := widget.NewLabel(path)
	folder_path := ""
	folder_path_wid := widget.NewLabel(path)
	pwd_wid := widget.NewPasswordEntry()
	opts := []string{"AES-256 Bit GCM with SHA256", "AES-256 Bit CBC with SHA256 and HMAC-SHA256", "AGE with Passhprase", "Ascon 128-bit with SHA256 truncated", "Ascon80pq 160-bit with SHA256 truncated", "Ascon128a 128-bit with SHA256 truncated", "xChaCha20-Poly1305 with SHA256", "Twofish 256-bit with SHA256 and HMAC-SHA256", "Serpent 256-bit with SHA256 and HMAC-SHA256", "AES+Twofish+Serpent", "AES+xChaCha20", "AES+xChaCha20+Ascon128a"}
	extraInfo := binding.NewString()
	extraInfo.Set("")
	sel_wid := widget.NewSelect(opts, func(s string) {
		switch s {
		case opts[9]:
			extraInfo.Set(combohelper.AES_TWOFISH_SERPENT_EXPLAIN)
		case opts[10]:
			extraInfo.Set(combohelper.AES_XCHACHA_EXPLAIN)
		case opts[11]:
			extraInfo.Set(combohelper.AES_XCHACHA_ASCONA_EXPLAIN)
		default:
			extraInfo.Set("")

		}
	})
	sel_wid.SetSelectedIndex(0)

	actbtn := widget.NewButton("Decrypt", func() {
		dat, err := os.ReadFile(path)
		if err != nil {
			show_err(w, err)
			return
		}

		switch sel_wid.SelectedIndex() {
		case 0: // GCM
			pwd := hashing.Sha256_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup

			wg.Add(1)

			var gerr error = nil

			go func() {
				defer wg.Done()

				out, err := aes.AesGCMDecrypt(pwd, dat)
				if err != nil {
					gerr = err
					return
				}

				tmpZipFile, err := os.CreateTemp("", "apitaesgcmfolderzip"+uuid.NewString())
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
				saveFolderPath := filepath.Join(folder_path, strings.Replace(filepath.Base(path), ".afagcm", "", 1)+"-decrypted")
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
				show_err(w, gerr)
				return
			}

			dialog.ShowInformation("Folder decrypted", "The folder was decrypted", w)
		case 1: // CBC
			pwd := hashing.Sha256_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup

			wg.Add(1)

			var gerr error = nil

			go func() {
				defer wg.Done()

				out, err := aes.AesHMACCBCDecrypt(pwd, dat)
				if err != nil {
					gerr = err
					return
				}

				tmpZipFile, err := os.CreateTemp("", "apitaescbcfolderzip"+uuid.NewString())
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
				saveFolderPath := filepath.Join(folder_path, strings.Replace(filepath.Base(path), ".afacbc", "", 1)+"-decrypted")
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
				show_err(w, gerr)
				return
			}

			dialog.ShowInformation("Folder decrypted", "The folder was decrypted", w)
		case 2: // AGE
			sid, err := age.NewScryptIdentity(pwd_wid.Text)
			if err != nil {
				show_err(w, err)
				return
			}

			var wg sync.WaitGroup

			wg.Add(1)

			var gerr error = nil

			go func() {
				defer wg.Done()

				reader, err := age.Decrypt(bytes.NewReader(dat), sid)
				if err != nil {
					gerr = err
					return
				}
				out, err := io.ReadAll(reader)
				if err != nil {
					gerr = err
					return
				}

				tmpZipFile, err := os.CreateTemp("", "apitagefolderzip"+uuid.NewString())
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
				saveFolderPath := filepath.Join(folder_path, strings.Replace(filepath.Base(path), ".zip.age", "", 1)+"-decrypted")
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
				show_err(w, gerr)
				return
			}

			dialog.ShowInformation("Folder decrypted", "The folder was decrypted", w)
		case 3: // Ascon
			pwd := hashing.Sha256_to_bytes_128bit([]byte(pwd_wid.Text))

			var wg sync.WaitGroup

			wg.Add(1)

			var gerr error = nil

			go func() {
				defer wg.Done()

				out, err := asconhelper.AsconDecrypt(pwd, dat)
				if err != nil {
					gerr = err
					return
				}

				tmpZipFile, err := os.CreateTemp("", "apitasconfolderzip"+uuid.NewString())
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
				saveFolderPath := filepath.Join(folder_path, strings.Replace(filepath.Base(path), ".afas", "", 1)+"-decrypted")
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
				show_err(w, gerr)
				return
			}

			dialog.ShowInformation("Folder decrypted", "The folder was decrypted", w)
		case 4: // Ascon80pq
			pwd := hashing.Sha256_to_bytes_160bit([]byte(pwd_wid.Text))

			var wg sync.WaitGroup

			wg.Add(1)

			var gerr error = nil

			go func() {
				defer wg.Done()

				out, err := asconhelper.AsconDecrypt(pwd, dat)
				if err != nil {
					gerr = err
					return
				}

				tmpZipFile, err := os.CreateTemp("", "apitascon80pqfolderzip"+uuid.NewString())
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
				saveFolderPath := filepath.Join(folder_path, strings.Replace(filepath.Base(path), ".afas80pq", "", 1)+"-decrypted")
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
				show_err(w, gerr)
				return
			}

			dialog.ShowInformation("Folder decrypted", "The folder was decrypted", w)
		case 5: // Ascon128a
			pwd := hashing.Sha256_to_bytes_128bit([]byte(pwd_wid.Text))

			var wg sync.WaitGroup

			wg.Add(1)

			var gerr error = nil

			go func() {
				defer wg.Done()

				out, err := asconhelper.Ascon128aDecrypt(pwd, dat)
				if err != nil {
					gerr = err
					return
				}

				tmpZipFile, err := os.CreateTemp("", "apitascon128afolderzip"+uuid.NewString())
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
				saveFolderPath := filepath.Join(folder_path, strings.Replace(filepath.Base(path), ".afas128a", "", 1)+"-decrypted")
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
				show_err(w, gerr)
				return
			}

			dialog.ShowInformation("Folder decrypted", "The folder was decrypted", w)
		case 6: // xcha
			pwd := hashing.Sha256_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup

			wg.Add(1)

			var gerr error = nil

			go func() {
				defer wg.Done()

				out, err := xchachahelper.XChaCha20Poly1305Decrypt(pwd, dat)
				if err != nil {
					gerr = err
					return
				}

				tmpZipFile, err := os.CreateTemp("", "apitxchafolderzip"+uuid.NewString())
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
				saveFolderPath := filepath.Join(folder_path, strings.Replace(filepath.Base(path), ".afxc20p1305", "", 1)+"-decrypted")
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
				show_err(w, gerr)
				return
			}

			dialog.ShowInformation("Folder decrypted", "The folder was decrypted", w)
		case 7: // twofish
			pwd := hashing.Sha256_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup

			wg.Add(1)

			var gerr error = nil

			go func() {
				defer wg.Done()

				out, err := twofish.TwofishHMACDecrypt(pwd, dat)
				if err != nil {
					gerr = err
					return
				}

				tmpZipFile, err := os.CreateTemp("", "apittwofishfolderzip"+uuid.NewString())
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
				saveFolderPath := filepath.Join(folder_path, strings.Replace(filepath.Base(path), ".afhtf", "", 1)+"-decrypted")
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
				show_err(w, gerr)
				return
			}

			dialog.ShowInformation("Folder decrypted", "The folder was decrypted", w)
		case 8: // serpent
			pwd := hashing.Sha256_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup

			wg.Add(1)

			var gerr error = nil

			go func() {
				defer wg.Done()

				out, err := serpent.SerpentHMACDecrypt(pwd, dat)
				if err != nil {
					gerr = err
					return
				}

				tmpZipFile, err := os.CreateTemp("", "apitserpentfolderzip"+uuid.NewString())
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
				saveFolderPath := filepath.Join(folder_path, strings.Replace(filepath.Base(path), ".afhsp", "", 1)+"-decrypted")
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
				show_err(w, gerr)
				return
			}

			dialog.ShowInformation("Folder decrypted", "The folder was decrypted", w)
		case 9: // ats
			pwd, err := hashing.SHAKE256_768_to_bytes([]byte(pwd_wid.Text))
			if err != nil {
				show_err(w, err)
				return
			}

			var wg sync.WaitGroup

			wg.Add(1)

			var gerr error = nil

			go func() {
				defer wg.Done()

				out, err := combohelper.AesTwofishSerpentDecrypt(pwd, dat)
				if err != nil {
					gerr = err
					return
				}

				tmpZipFile, err := os.CreateTemp("", "apitatfspfolderzip"+uuid.NewString())
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
				saveFolderPath := filepath.Join(folder_path, strings.Replace(filepath.Base(path), ".afatfsp", "", 1)+"-decrypted")
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
				show_err(w, gerr)
				return
			}

			dialog.ShowInformation("Folder decrypted", "The folder was decrypted", w)
		case 10: // axc
			pwd := hashing.Sha3_512_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup

			wg.Add(1)

			var gerr error = nil

			go func() {
				defer wg.Done()

				out, err := combohelper.AesxChaCha20Poly1305Decrypt(pwd, dat)
				if err != nil {
					gerr = err
					return
				}

				tmpZipFile, err := os.CreateTemp("", "apitaxcfolderzip"+uuid.NewString())
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
				saveFolderPath := filepath.Join(folder_path, strings.Replace(filepath.Base(path), ".afaxc", "", 1)+"-decrypted")
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
				show_err(w, gerr)
				return
			}

			dialog.ShowInformation("Folder decrypted", "The folder was decrypted", w)
		case 11: // axcasa
			pwd, err := hashing.SHAKE256_640_to_bytes([]byte(pwd_wid.Text))
			if err != nil {
				show_err(w, err)
				return
			}

			var wg sync.WaitGroup

			wg.Add(1)

			var gerr error = nil

			go func() {
				defer wg.Done()

				out, err := combohelper.AesXChaCha20Poly1305Ascon128aDecrypt(pwd, dat)
				if err != nil {
					gerr = err
					return
				}

				tmpZipFile, err := os.CreateTemp("", "apitaxcaafolderzip"+uuid.NewString())
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
				saveFolderPath := filepath.Join(folder_path, strings.Replace(filepath.Base(path), ".afaxcasa", "", 1)+"-decrypted")
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
				show_err(w, gerr)
				return
			}

			dialog.ShowInformation("Folder decrypted", "The folder was decrypted", w)

		}

	})
	actbtn.Disable()

	pwd_wid.OnChanged = func(s string) {
		if len(s) != 0 && path != "" && folder_path != "" {
			actbtn.Enable()
		} else {
			actbtn.Disable()
		}
	}

	return container.NewBorder(
		container.NewGridWithColumns(
			3,
			backbtn,
			widget.NewLabel("Folder - Decrypt"),
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
								show_err(w, err)
								return
							}

							path = uc.URI().Path()
							path_wid.SetText(uc.URI().Name())
							if folder_path != "" && path != "" {
								actbtn.Enable()
							} else {
								actbtn.Disable()
							}
						}, w)
					}),
				),
				widget.NewLabel("Folder output"),
				container.NewGridWithColumns(
					2,
					folder_path_wid,
					widget.NewButton("Select folder", func() {
						dialog.ShowFolderOpen(func(uc fyne.ListableURI, err error) {
							if uc == nil {
								return
							}
							if err != nil {
								show_err(w, err)
								return
							}

							folder_path = uc.Path()
							folder_path_wid.SetText(uc.Name())
							if folder_path != "" && path != "" {
								actbtn.Enable()
							} else {
								actbtn.Disable()
							}
						}, w)
					}),
				),
				widget.NewLabel("Password"),
				pwd_wid,
				widget.NewLabel("Cipher"),
				sel_wid,
				widget.NewLabel(""),
				widget.NewLabelWithData(extraInfo),
			),
		),
	)

}
