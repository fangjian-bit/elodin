#+build !linux
package main

// Transparent huge pages are a Linux feature; see thp_linux.odin.
@(private)
disable_huge_pages :: proc() {}
