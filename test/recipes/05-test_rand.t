#! /usr/bin/env perl
# Copyright 2015-2020 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;
use OpenSSL::Test;

plan tests => 2;
setup("test_rand");

ok(run(test(["drbgtest"])));
ok(run(test(["drbg_cavs_test"])));
# commented out due to long running time
#ok(run(test(["drbg_extra_test"])));
