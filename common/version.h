#pragma once

// Project version (unified across both ports). Overridable at build time with
// -DFRAGMENT_VERSION="x.y.z" -- the release workflow injects the git tag --
// and defaults to the in-development version otherwise.
#ifndef FRAGMENT_VERSION
#define FRAGMENT_VERSION "1.1.0-dev"
#endif
