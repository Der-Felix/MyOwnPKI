package main

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
)

// optimizeFile rewrites the PNG at path as small as possible without changing
// a single pixel, and returns the size before and after.
func optimizeFile(path string) (before, after int, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	out, err := optimize(data)
	if err != nil {
		return 0, 0, err
	}
	if len(out) >= len(data) {
		return len(data), len(data), nil
	}
	if err := os.WriteFile(path, out, 0o644); err != nil { //nolint:gosec // images in the repository are world-readable
		return 0, 0, err
	}
	return len(data), len(out), nil
}

// optimize re-encodes a PNG losslessly: an indexed palette when the image has
// at most 256 colors, otherwise 8-bit RGB without alpha when it is opaque,
// both with the best zlib compression. Metadata chunks are dropped. The
// result is decoded again and compared pixel by pixel.
func optimize(data []byte) ([]byte, error) {
	src, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	var img image.Image = toNRGBA(src)
	if p := toPaletted(src); p != nil {
		img = p
	}
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if encErr := enc.Encode(&buf, img); encErr != nil {
		return nil, encErr
	}
	check, err := png.Decode(bytes.NewReader(buf.Bytes()))
	if err != nil {
		return nil, err
	}
	if !samePixels(src, check) {
		return nil, errors.New("re-encoded image differs from the original")
	}
	return buf.Bytes(), nil
}

// toPaletted returns src as an indexed image, or nil if it has more than 256
// distinct colors (then a palette would lose information).
func toPaletted(src image.Image) *image.Paletted {
	b := src.Bounds()
	index := make(map[color.NRGBA]uint8, 256)
	var palette color.Palette
	dst := image.NewPaletted(b, nil)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			c, ok := color.NRGBAModel.Convert(src.At(x, y)).(color.NRGBA)
			if !ok {
				return nil
			}
			i, seen := index[c]
			if !seen {
				if len(palette) == 256 {
					return nil
				}
				i = uint8(len(palette)) //nolint:gosec // len(palette) < 256 here
				index[c] = i
				palette = append(palette, c)
			}
			dst.SetColorIndex(x, y, i)
		}
	}
	dst.Palette = palette
	return dst
}

// toNRGBA copies src into an NRGBA image; the PNG encoder writes it as
// 8-bit RGB when every pixel is opaque.
func toNRGBA(src image.Image) *image.NRGBA {
	dst := image.NewNRGBA(src.Bounds())
	draw.Draw(dst, dst.Bounds(), src, src.Bounds().Min, draw.Src)
	return dst
}

func samePixels(a, b image.Image) bool {
	if a.Bounds() != b.Bounds() {
		return false
	}
	r := a.Bounds()
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			if color.NRGBAModel.Convert(a.At(x, y)) != color.NRGBAModel.Convert(b.At(x, y)) {
				return false
			}
		}
	}
	return true
}
