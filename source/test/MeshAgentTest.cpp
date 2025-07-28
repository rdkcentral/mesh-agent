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
#include <gmock/gmock.h>
#include "test/MockUtils.h"

extern "C" {
#include "meshagent.h"
#include "meshsync_msgs.h"
int Mesh_EthBhaulPodVlanSetup(int PodIdx, bool isOvsMode);
}


UtilsMock * g_utilsMock = NULL;  /* This is the actual definition of the mock obj */

using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;

class MeshAgentTestFixture : public ::testing::Test {
    protected:
        UtilsMock mockedUtils;

        MeshAgentTestFixture()
        {
            g_utilsMock = &mockedUtils;
        }
        virtual ~MeshAgentTestFixture()
        {
            g_utilsMock = NULL;
        }

        virtual void SetUp()
        {
            /**MeshInfo("%s %s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_info()->test_case_name(),
                ::testing::UnitTest::GetInstance()->current_test_info()->name());
                **/
        }

        virtual void TearDown()
        {
            /**
            MeshInfo("%s %s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_info()->test_case_name(),
                ::testing::UnitTest::GetInstance()->current_test_info()->name());
                **/
        }

        static void SetUpTestCase()
        {
            /**
            //MeshInfo("%s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_case()->name());
                **/
        }

        static void TearDownTestCase()
        {
        /**
            MeshInfo("%s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_case()->name());
                **/
        }
};

TEST(MeshAgent, update_connected_device_mac_null_test)
{
    ASSERT_EQ(false, Mesh_UpdateConnectedDevice(NULL, NULL, NULL, NULL));
}

TEST_F(MeshAgentTestFixture, ethbhaul_ovs_vlan_setup_test)
{
    int PodIdx = 2;

    EXPECT_CALL(*g_utilsMock, v_secure_system(StrEq("/sbin/vconfig add ethpod2 101")))
            .Times(1)
            .WillOnce(Return(0));

    EXPECT_CALL(*g_utilsMock, v_secure_system(StrEq("/sbin/vconfig add ethpod2 106")))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_utilsMock, v_secure_system(StrEq("/sbin/ifconfig ethpod2.101 up")))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_utilsMock, v_secure_system(StrEq("/sbin/ifconfig ethpod2.106 up")))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_utilsMock, v_secure_system(StrEq("/usr/bin/ovs-vsctl add-port brlan1 ethpod2.101")))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_utilsMock, v_secure_system(StrEq("/usr/bin/ovs-vsctl add-port br106 ethpod2.106")))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(0, Mesh_EthBhaulPodVlanSetup(PodIdx, true));
}

TEST_F(MeshAgentTestFixture, ethbhaul_vlan_setup_test)
{

    int PodIdx = 2;

    EXPECT_CALL(*g_utilsMock, v_secure_system(StrEq("/sbin/vconfig add ethpod2 101")))
            .Times(1)
            .WillOnce(Return(0));

    EXPECT_CALL(*g_utilsMock, v_secure_system(StrEq("/sbin/vconfig add ethpod2 106")))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_utilsMock, v_secure_system(StrEq("/sbin/ifconfig ethpod2.101 up")))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_utilsMock, v_secure_system(StrEq("/sbin/ifconfig ethpod2.106 up")))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_utilsMock, v_secure_system(StrEq("brctl addif brlan1 ethpod2.101")))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_utilsMock, v_secure_system(StrEq("brctl addif br106 ethpod2.106")))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(0, Mesh_EthBhaulPodVlanSetup(PodIdx, false));
}



