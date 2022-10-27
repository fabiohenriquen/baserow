export default (client, $featureFlags) => {
  return {
    // TODO implement once endpoint exists
    get(group) {
      if ($featureFlags.includes('roles')) {
        return {
          data: [
            { uid: 'ADMIN' },
            { uid: 'BUILDER' },
            { uid: 'EDITOR' },
            { uid: 'COMMENTER' },
            { uid: 'VIEWER' },
          ],
        }
      }
      return {
        data: [{ uid: 'ADMIN' }, { uid: 'MEMBER' }],
      }
    },
  }
}
