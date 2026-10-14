import { render, screen, waitFor } from '@testing-library/react';
import { useEffect, useState } from 'react';
import { describe, expect, it, vi } from 'vitest';

import { queueList } from './invoke';
import queueItems from './fixtures/queue_item.json';
import type { QueueItem } from './types';

vi.mock('./invoke', () => ({ queueList: vi.fn() }));

function Count() {
  const [items, setItems] = useState<QueueItem[] | null>(null);
  useEffect(() => {
    void queueList().then(setItems);
  }, []);
  return <p>{items === null ? 'loading' : `${items.length} items`}</p>;
}

describe('invoke.ts can be mocked in a component test', () => {
  it('renders what the mocked wrapper returns', async () => {
    vi.mocked(queueList).mockResolvedValue(queueItems as unknown as QueueItem[]);
    render(<Count />);
    await waitFor(() => expect(screen.getByText('1 items')).toBeTruthy());
  });
});