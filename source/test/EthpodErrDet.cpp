/*
* If not stated otherwise in this file or this component's LICENSE file the
* following copyright and licenses apply:
*
* Copyright 2018 RDK Management
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include <gtest/gtest.h>

extern "C" {
#include "MeshAgentSsp/ethpod_error_det.h"
}

TEST(EthPodErrDet, test1234)
{
    ASSERT_EQ(false, meshHandleEvent("d0:6e:de:5e:65:dc", DHCP_ACK_PRIV_EVENT));
    ASSERT_EQ(true, meshAddPod("d0:6e:de:5e:65:dc"));
    ASSERT_EQ(true, meshAddPod("d0:6e:de:5e:65:dc"));
    ASSERT_EQ(true, meshAddPod("d0:6e:de:5e:65:dd"));

    ASSERT_EQ(true, meshHandleEvent("d0:6e:de:5e:65:dc", DHCP_ACK_PRIV_EVENT)); //handle event okay
    ASSERT_EQ(false, meshHandleEvent("ab:6e:de:5e:65:dc", DHCP_ACK_PRIV_EVENT)); //No pod with this mac
}
