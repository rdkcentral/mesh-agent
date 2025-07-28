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

#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#define GTEST_REPORT_DIRECTORY "/tmp/Gtest_Report"
#define GTEST_REPORT_FILEPATH "MeshAgent_gtest_report.xml"
#define GTEST_REPORT_FILEPATH_SIZE 128

GTEST_API_ int main(int argc, char *argv[])
{
    char filePath[GTEST_REPORT_FILEPATH_SIZE] = {0}; // Test Results Full File Path
    snprintf(filePath, GTEST_REPORT_FILEPATH_SIZE, "xml:%s/%s",
            GTEST_REPORT_DIRECTORY,GTEST_REPORT_FILEPATH);
    ::testing::GTEST_FLAG(output) = filePath;
    ::testing::InitGoogleMock(&argc, argv);
    return RUN_ALL_TESTS();
}
