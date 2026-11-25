// Package imagefs reads the parts of a container image's filesystem that
// identify the Java runtimes in it, without extracting the image.
//
// Each layer is streamed once and reduced to a summary: the path and type of
// every entry, the targets of links, the whiteouts, and the content of the
// small files named "release". The summaries of the layers are stacked bottom
// to top under the OCI layer rules to get the final view of the filesystem,
// and the Java runtimes are found in that view.
//
// Layers come from a registry (the manifest's layers, streamed and verified
// as they are read) or from the Docker Engine's image export. Verified layer
// summaries are cached by diffID, so a later run reads only what is new.
// Every run is bounded by per-cycle byte budgets and a per-image time limit;
// what cannot finish is reported as deferred (try again next cycle) or
// permanent (do not try again until the limits or the program change).
package imagefs
