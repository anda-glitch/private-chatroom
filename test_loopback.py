# test_loopback.py
import pyaudio
import opuslib

SAMPLE_RATE = 16000
CHANNELS = 1
CHUNK = 960
FORMAT = pyaudio.paInt16

p = pyaudio.PyAudio()

stream_in = p.open(
    format=FORMAT, channels=CHANNELS,
    rate=SAMPLE_RATE, input=True,
    frames_per_buffer=CHUNK
)

stream_out = p.open(
    format=FORMAT, channels=CHANNELS,
    rate=SAMPLE_RATE, output=True,
    frames_per_buffer=CHUNK
)

encoder = opuslib.Encoder(SAMPLE_RATE, CHANNELS, 'voip')
decoder = opuslib.Decoder(SAMPLE_RATE, CHANNELS)

print("Loopback test — speak and you should hear yourself (Ctrl+C to stop)")

try:
    while True:
        pcm = stream_in.read(CHUNK, exception_on_overflow=False)
        compressed = encoder.encode(pcm, CHUNK)   # encode
        pcm_back = decoder.decode(compressed, CHUNK)  # decode
        stream_out.write(pcm_back)                # play
except KeyboardInterrupt:
    pass

stream_in.stop_stream()
stream_out.stop_stream()
stream_in.close()
stream_out.close()
p.terminate()
print("Done")
