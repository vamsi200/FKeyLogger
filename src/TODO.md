- inject into a running python process and get its modules like gdb -> nope not a good idea buddy => because it could crash things. We are using py-spy as an alt for now
- Add proper logging
- We are only checking python files. We have to up our game
- !> [!IMPORTANT]
> Check Network part - done some of it

- Add user Prompt to make a process `trusted`
- uinput detection - virtual keyboard
- LD_PRELOAD detection
- Wayland Checks
- Add -p pid option for checking a particular pid
- Add Checks -> like precautions:
  checking bashrc, zshrc files
  check if some process is running `history -a` or something like that, i.e logging history to a file
  PAM abuse

- Maybe in way future, implement sandboxing?

