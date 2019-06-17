using System.Collections;

namespace MS.Dbg
{
    // Public to be callable from scripts
    public static class ScriptHelpers
    {
        // This is roughly equivalent to the internal PSObjectHelper.GetEnumerable,
        // which counts IDictionaries as IEnumerable even though LanguagePrimitives does not.
        public static IEnumerable GetEnumerable( object obj )
        {
            IEnumerable enumerable = System.Management.Automation.LanguagePrimitives.GetEnumerable( obj );
            if( enumerable != null )
            {
                return enumerable;
            }
            return obj as IDictionary;

        }
    }
}