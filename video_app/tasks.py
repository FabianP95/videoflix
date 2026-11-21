import subprocess


def convert_to_480p(source):
    target = source + "_480p"
    cmd = f'ffmpeg -i "{source}" -s hd720 -c:v libx264 -crf 23 -c:a aac -strict -2 "{target}"'
    subprocess.run(cmd, check=False)
