//go:build !windows

package atomicfile

import "os"

// syncDir flushes the directory entry created by the rename.
//
// Renaming into place is atomic, but atomicity and durability are different
// properties: the rename can still be sitting in the filesystem's metadata
// journal when the machine loses power, and on recovery the directory can
// show the old name, or neither name. fsync on the containing directory is
// what makes the new entry durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
