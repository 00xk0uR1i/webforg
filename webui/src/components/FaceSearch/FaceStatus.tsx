import { FaceSearchPhase } from '../../types/faceSearch'
import { InlineStatus, Spinner } from '../UI'

interface FaceStatusProps {
  phase: FaceSearchPhase
}

export function FaceStatus({ phase }: FaceStatusProps) {
  switch (phase) {
    case 'uploading':
      return <Spinner text="Uploading image..." color="webforge" />
    case 'detecting':
      return <Spinner text="Detecting faces..." color="cyan" />
    case 'embedding':
      return <Spinner text="Generating face embedding..." color="green" />
    case 'searching':
      return <Spinner text="Searching face index..." color="webforge" />
    case 'face-selection':
      return (
        <InlineStatus status="info">
          Multiple faces detected. Select a face to search.
        </InlineStatus>
      )
    default:
      return null
  }
}
