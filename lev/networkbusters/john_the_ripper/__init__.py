from levrt import annot
from . import john
from .john_workflow import Base_Workflow, Wordlist_Workflow


__lev__ = annot.meta([john, Base_Workflow, Wordlist_Workflow, Wordlist_Workflow_User_Profiling]) #, john_workflow])