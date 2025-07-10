- inject into a running python process and get its modules like gdb -> nope not a good idea buddy => because it could crash things. We are using py-spy as an alt for now
- !> [!IMPORTANT]
> Check Network part - done some of it

- add reasons to functions that are applicable
- Add user Prompt to make a process `trusted`
- uinput detection - virtual keyboard
- LD_PRELOAD detection
- Wayland Checks
- Add -p pid option for checking a particular pid
- Add Checks -> like precautions:
  checking bashrc, zshrc files
  check if some process is running `history -a` or something like that, i.e logging history to a file
  PAM abuse

IMPORTANT:
- Add No Trust Process option during the scanning and monitoring - done.
- An option to Trust certain processes - done.
- Add log option to reasons for more verbose reasoning
- Add log, explaining why a process is trusted
- Add a initial setup flow, that get all the details about input devices etc..

- Maybe in way future, implement sandboxing?

