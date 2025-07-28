/*
* If not stated otherwise in this file or this component's LICENSE file the
* following copyright and licenses apply:
*
* Copyright 2020 RDK Management
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


#include <stdarg.h>
#include "test/MockUtils.h"

extern UtilsMock * g_utilsMock;   /* This is just a declaration! The actual mock
                                     obj is defined globally in the test file. */

// Mock Method
extern "C" int v_secure_system(const char * cmd, ...)
{
    if (!g_utilsMock)
    {
        return 0;
    }

    char format[250] = { 0 };

    va_list argptr;
    va_start(argptr, cmd);
    vsnprintf(format, sizeof(format), cmd, argptr);
    va_end(argptr);

    return g_utilsMock->v_secure_system(format);
}

extern "C" int access(const char * pathname, int mode)
{
    if (!g_utilsMock)
    {
        return -1;
    }
    return g_utilsMock->access(pathname, mode);
}
