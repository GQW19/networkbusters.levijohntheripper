from levrt import annot
from . import john
from .john_workflow import Base_Workflow


__lev__ = annot.meta([john, Base_Workflow]) #, john_workflow])