/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

// strict expansion map disallows dropping properties when expanding by default
module.exports = info => {
  if(info.unmappedProperty) {
    throw new Error('The property "' +
       info.unmappedProperty + '" in the input ' +
      'was not defined in the context.');
  }
};
