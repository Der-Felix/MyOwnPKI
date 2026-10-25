package agent

import "os"

func previousOwner(os.FileInfo) (int, int) { return -1, -1 }
