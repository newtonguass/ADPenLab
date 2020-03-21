function translateAM{
    param(
        [Parameter(Mandatory=$true)]
        [String]$bit,

        [Parameter(Mandatory=$false)]
        [String]$dictPath="./accessMask.csv"
         )
    $dict=import-csv $dictPath
    $right = ""
    foreach($i in 0..$dict.length){
        if([int]$bit -band [int]$dict[$i].Bit){
            $right = $right + ($dict[$i].Description+"," + $dict[$i].Right) + ":"
        }
    }
    if($right.Length -eq 0){
        $right = "not found"
    }
    return $right.Substring(0, $right.Length-1)
}
