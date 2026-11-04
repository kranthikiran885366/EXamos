const APPLICATION_STAGES = {
  SUBMITTED: {
    stage: 'Submitted',
    nextAction: 'Wait for the platform review team to assess the application.',
    owner: 'Platform review team',
  },
  UNDER_REVIEW: {
    stage: 'Under review',
    nextAction: 'The platform review team owns the next action. Check back for an updated status.',
    owner: 'Platform review team',
  },
  VERIFICATION_PENDING: {
    stage: 'Verification pending',
    nextAction: 'Follow any verification instructions provided by your institution contact.',
    owner: 'Institution representative',
  },
  MORE_INFORMATION_REQUIRED: {
    stage: 'Information requested',
    nextAction: 'Contact the platform review team using your reference and provide the requested information.',
    owner: 'Institution representative',
  },
  APPROVED: {
    stage: 'Approved — awaiting provisioning',
    nextAction: 'The platform provisioning team must create the institution environment.',
    owner: 'Platform provisioning team',
  },
  PROVISIONED: {
    stage: 'Provisioned',
    nextAction: 'Provisioning is recorded, but the institution is not yet authorized for live operations.',
    owner: 'Platform operations',
  },
  REJECTED: {
    stage: 'Rejected',
    nextAction: 'Contact the platform review team if you need clarification or wish to reapply.',
    owner: 'Institution representative',
  },
};

export function getApplicationLifecycle(status, institutionStatus, adminSetupComplete) {
  const key = String(status || '').toUpperCase();
  const lifecycle = APPLICATION_STAGES[key] || {
    stage: 'Status unavailable',
    nextAction: 'Contact platform support with your application reference.',
    owner: 'Platform support',
  };
  const isLive = String(institutionStatus || '').toLowerCase() === 'active';

  if (key === 'PROVISIONED' && isLive) {
    return {
      stage: 'Authorized for live operations',
      nextAction: 'Your institution is active. Contact your institution administrator for account and exam setup.',
      owner: 'Institution administrator',
    };
  }

  if (key === 'PROVISIONED' && adminSetupComplete === false) {
    return {
      stage: 'Admin setup pending',
      nextAction: 'Platform operations and the institution must finish primary administrator account setup and multi-factor authentication before live operations can be authorized.',
      owner: 'Institution administrator and platform operations',
    };
  }

  return lifecycle;
}
