# one_gadget_finder
One-gadget is code that invokes "/bin/sh" without any arguments, so all you need to do is jump to its address.
This library provides the function to find offsets of one-gadget in libc.

## Requirements
- capstone
- pyelftools

You can install these requrements by typing following commands.

```bash
pip3 install --user capstone pyelftools
```

## Reference
- [one_gadget](https://github.com/david942j/one_gadget)
- [The one-gadget in glibc](https://david942j.blogspot.com/2017/02/project-one-gadget-in-glibc.html) (blog post by the author of [one_gadget](https://github.com/david942j/one_gadget))
