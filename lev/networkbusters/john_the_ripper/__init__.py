from levrt import annot
from . import john
from .john_workflow import JTR_Base_Workflow, JTR_CeWL_Wordlist_Workflow, JTR_CUPP_Wordlist_Workflow, JTR_CeWL_CUPP_Wordlist_Workflow


__lev__ = annot.meta([john, JTR_Base_Workflow, JTR_CeWL_Wordlist_Workflow, JTR_CUPP_Wordlist_Workflow, JTR_CeWL_CUPP_Wordlist_Workflow]) #, john_workflow])