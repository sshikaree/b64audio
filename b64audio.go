package b64audio

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"log"

	"github.com/gordonklaus/portaudio"
)

const (
	BLOCK_SIZE = 480 // 60ms at 8kHz/8bit, for Opus encoding
)

// WAVInfo contains wav information
type WAVInfo struct {
	Id              [4]byte
	Length          int32
	WavFmt          [8]byte
	Format          int32
	PCM             int16
	Channels        int16
	Freq            int32
	BytesPerSecond  int32
	BytesPerCapture int16
	BitsPerSample   int16
	Data            [4]byte
	BytesInData     int32
}

// GetWAVInfo gets information from wav chunk
func GetWAVInfo(chunk []byte) (*WAVInfo, error) {
	info := WAVInfo{}
	err := binary.Read(bytes.NewReader(chunk), binary.LittleEndian, &info)
	return &info, err
}

// DecodePayload converts base64 to []byte
func DecodePayload(payload []byte) ([]byte, error) {
	buf := make([]byte, base64.StdEncoding.DecodedLen(len(payload)))
	n, err := base64.StdEncoding.Decode(buf, payload)
	return buf[:n], err
	//return base64.StdEncoding.DecodeString(string(payload))
}

// EncodePayloadToString converts []byte to base64 string
func EncodePayloadToString(chunk []byte) string {
	return base64.StdEncoding.EncodeToString(chunk)
}

// EncodePayload retruns the base64 encoding of input
func EncodePayload(chunk []byte) []byte {
	buf := make([]byte, base64.StdEncoding.EncodedLen(len(chunk)))
	base64.StdEncoding.Encode(buf, chunk)
	return buf
}

// PlayWAVChunk plays wav format chunk
func PlayWAVChunk(chunk []byte) error {
	chunk = chunk[44:]
	buf := make([]uint8, len(chunk))
	stream, err := portaudio.OpenDefaultStream(0, 1, 8000, 8, &buf)
	if err != nil {
		return err
	}
	defer stream.Close()
	if err = stream.Start(); err != nil {
		return err
	}
	defer stream.Stop()

	reader := bytes.NewReader(chunk)
	if err = binary.Read(reader, binary.LittleEndian, buf); err != nil {
		return err
	}
	if err = stream.Write(); err != nil {
		return err
	}
	return nil

}

// PlayChunk plays raw PCM chunk
func PlayChunk(chunk []byte) error {
	stream, err := portaudio.OpenDefaultStream(0, 1, 8000, 8, &chunk)
	if err != nil {
		return err
	}
	defer stream.Close()
	if err = stream.Start(); err != nil {
		return err
	}
	defer stream.Stop()

	if err = stream.Write(); err != nil {
		return err
	}
	return nil

}

// ContinuousPlay opens audio stream and plays raw pcm chunks, requesting ingoing channel.
// It's blocking function.
func ContinuousPlay(ingoing chan []byte) error {
	chunk := make([]uint8, BLOCK_SIZE)
	stream, err := portaudio.OpenDefaultStream(0, 1, 8000, 8, &chunk)
	if err != nil {
		return err
	}
	defer stream.Close()
	if err = stream.Start(); err != nil {
		return err
	}
	defer stream.Stop()

	for {
		chunk = <-ingoing
		if err = stream.Write(); err != nil {
			log.Println(err)
		}
	}
}

func RecordWAVChunk() ([]byte, error) {
	buf := make([]uint8, BLOCK_SIZE)
	stream, err := portaudio.OpenDefaultStream(1, 0, 8000, BLOCK_SIZE, &buf)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	if err = stream.Start(); err != nil {
		return nil, err
	}
	defer stream.Stop()

	if err = stream.Read(); err != nil {
		return nil, err
	}
	var chunk []byte
	writer := bytes.NewBuffer(chunk)
	if err = binary.Write(writer, binary.LittleEndian, &buf); err != nil {
		return nil, err
	}
	return writer.Bytes(), nil
}

// RecordChunk records audio chunk
func RecordChunk() ([]byte, error) {
	buf := make([]uint8, BLOCK_SIZE)
	stream, err := portaudio.OpenDefaultStream(1, 0, 8000, BLOCK_SIZE, &buf)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	if err = stream.Start(); err != nil {
		return nil, err
	}
	defer stream.Stop()

	if err = stream.Read(); err != nil {
		return nil, err
	}

	return buf, err
}

// ContinuousRecord records chunks and puts them into channel.
// It's blocking function.
func ContinuousRecord(outgoing chan []byte) error {
	buf := make([]uint8, BLOCK_SIZE)
	stream, err := portaudio.OpenDefaultStream(1, 0, 8000, BLOCK_SIZE, &buf)
	if err != nil {
		return err
	}
	defer stream.Close()
	if err = stream.Start(); err != nil {
		return err
	}
	defer stream.Stop()

	for {
		if err = stream.Read(); err != nil {
			return err
		}
		outgoing <- buf
	}
}
