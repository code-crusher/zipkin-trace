/*
 * Copyright The OpenZipkin Authors
 * SPDX-License-Identifier: Apache-2.0
 */
import React from 'react';

import { describe, it, expect, afterEach } from 'vitest';
import { cleanup, screen } from '@testing-library/react';
import render from '../../test/util/render-with-default-settings';
import DiscoverPage from './DiscoverPage';

describe('<DiscoverPage />', () => {
  afterEach(cleanup);

  // See https://github.com/openzipkin/zipkin/issues/3508
  it('renders the discover screen when search is enabled', () => {
    render(<DiscoverPage />, {
      uiConfig: {
        searchEnabled: true,
      },
    });
    expect(
      screen.queryByText(
        'Searching has been disabled via the searchEnabled property. You can still view specific traces of which you know the trace id by entering it in the "Trace ID..." textbox on the top-right.',
      ),
    ).toBeNull();
  });

  it('shows a notice when search is disabled', () => {
    render(<DiscoverPage />, {
      uiConfig: {
        searchEnabled: false,
      },
    });
    expect(
      screen.getByText(
        'Searching has been disabled via the searchEnabled property. You can still view specific traces of which you know the trace id by entering it in the "Trace ID..." textbox on the top-right.',
      ),
    ).toBeDefined();
  });
});
