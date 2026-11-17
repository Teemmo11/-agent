import time
from .artifacts import utc_now
STATES = ['CREATED', 'INPUT_SNAPSHOTTED', 'PREFLIGHT', 'ANALYZING', 'GENERATING',
          'NORMALIZING', 'FORMALIZING', 'VERIFYING', 'SUMMARIZING', 'FINISHED']
class StateMachine:
    def __init__(self, store):
        self.store, self.state, self.sequence = store, 'CREATED', 0
        self.stage_started=time.monotonic()
        self.save()
    def save(self):
        if hasattr(self.store,'trace'):
            self.store.trace.emit('stage.changed',state=self.state)
        self.store.write('checkpoint.json', {'state': self.state, 'sequence': self.sequence,
          'updated_at': utc_now(), 'resume_supported': False})
    def transition(self, state):
        if self.state in ('FINISHED','FAILED') or (state != 'FAILED' and STATES.index(state) != STATES.index(self.state)+1):
            raise ValueError(f'Illegal state transition {self.state} -> {state}')
        if hasattr(self.store,'trace'):
            self.store.trace.emit('stage.finished',state=self.state,duration_ms=round((time.monotonic()-self.stage_started)*1000,3))
        self.stage_started=time.monotonic()
        self.state, self.sequence = state, self.sequence+1
        self.save()
