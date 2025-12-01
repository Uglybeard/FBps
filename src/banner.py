import datetime
import pathlib

parent_dir = pathlib.Path(__file__).parent.parent

def show_banner(num_threads):
    """
    Displays the banner and start-up information for the fuzzing process.
    """

    now = datetime.datetime.now().astimezone()
    current_time = now.strftime("%Y-%m-%d %H:%M %Z")

    try:
        with open(parent_dir / "banner" / "banner.txt", "r") as banner_file:
            banner = banner_file.read()
            print(banner)
    except FileNotFoundError:
        print("[!] Banner file not found, skipping banner display.")

    print(f"Starting FBps at {current_time} with {num_threads} threads")
