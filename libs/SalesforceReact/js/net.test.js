/*
 * Copyright (c) 2018-present, salesforce.com, inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided
 * that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the
 * following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
 * the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * Neither the name of salesforce.com, inc. nor the names of its contributors may be used to endorse or
 * promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 'AS IS' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

import { assert } from 'chai';
import { registerTest, testDone } from './react.force.test';
import { net } from 'react-native-force';

const apiVersion = 'v42.0';

testGetApiVersion = () => {
    assert.equal(net.getApiVersion(), apiVersion);
};

testVersions = () => {
    net.versions(
        (response) => {
            assert.deepEqual(response[response.length-1], {'label':'Spring ’18','url':'/services/data/v42.0','version':'42.0'}, 'Wrong latest version');
            testDone(true);
        },
        (error) => { throw error; }
    );
    
    return false; // not done
};

testResources = () => {
    net.resources(
        (response) => {
            assert.equal(response.connect, '/services/data/' + apiVersion + '/connect', 'Wrong url for connect resource');
            testDone(true);
        },
        (error) => { throw error; }
    );
    
    return false; // not done
};

testDescribeGlobal = () => {
    net.describeGlobal(
        (response) => {
            assert.isArray(response.sobjects, 'Expected sobjects array');
            testDone(true);
        },
        (error) => { throw error; }
    );
    
    return false; // not done
};

testMetaData = () => {
    net.metadata(
        'account',
        (response) => {
            assert.isObject(response.objectDescribe, 'Expected objectDescribe object');
            assert.isArray(response.recentItems, 'Expected recentItems array');
            testDone(true);
        },
        (error) => { throw error; }
    );
    
    return false; // not done
};

testDescribe = () => {
    net.describe(
        'account',
        (response) => {
            assert.isFalse(response.custom, 'Expected custom to be false');
            assert.isArray(response.fields, 'Expected fields object');
            testDone(true);
        },
        (error) => { throw error; }
    );
    
    return false; // not done
};


registerTest(testGetApiVersion);
registerTest(testVersions);
registerTest(testResources);
registerTest(testDescribeGlobal);
registerTest(testMetaData);
registerTest(testDescribe);
