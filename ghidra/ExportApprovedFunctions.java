// Export approved native functions as deterministic per-body intermediates.
//@category Aniimo

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;

public class ExportApprovedFunctions extends GhidraScript {
    private static String json(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder result = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            switch (character) {
                case '\\': result.append("\\\\"); break;
                case '"': result.append("\\\""); break;
                case '\n': result.append("\\n"); break;
                case '\r': result.append("\\r"); break;
                case '\t': result.append("\\t"); break;
                default:
                    if (character < 0x20) {
                        result.append(String.format("\\u%04x", (int) character));
                    }
                    else {
                        result.append(character);
                    }
            }
        }
        return result.append('"').toString();
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(String.format("%02x", value & 0xff));
        }
        return result.toString();
    }

    private static String digestHex(MessageDigest digest) {
        return hex(digest.digest());
    }

    private static boolean validC(String text) {
        if (text == null) {
            return false;
        }
        String stripped = text.strip();
        return !stripped.isEmpty() && stripped.contains("{") && stripped.contains("}");
    }

    private static long relative(Address address, Address imageBase) {
        return address.subtract(imageBase);
    }

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length < 3) {
            throw new IllegalArgumentException(
                "Expected output directory, timeout seconds, and maximum primary timeouts");
        }
        Path output = Paths.get(arguments[0]);
        int timeoutSeconds = Integer.parseInt(arguments[1]);
        int maximumTimeouts = Integer.parseInt(arguments[2]);
        int difficultTimeoutSeconds = arguments.length > 3 ? Integer.parseInt(arguments[3]) : 120;
        int maximumDifficultBodies = arguments.length > 4 ? Integer.parseInt(arguments[4]) : 2;
        int maximumDifficultWallSeconds = arguments.length > 5 ? Integer.parseInt(arguments[5]) : 240;
        Path assemblyRoot = output.resolve("asm");
        Path cRoot = output.resolve("c");
        Files.createDirectories(assemblyRoot);
        Files.createDirectories(cRoot);

        Address imageBase = currentProgram.getImageBase();
        AddressSet attributed = new AddressSet();
        int ordinal = 0;
        int timeoutCount = 0;
        int cCount = 0;
        int asmOnlyCount = 0;
        int disassemblyFailedCount = 0;
        int pendingCount = 0;
        int difficultAttemptCount = 0;
        int difficultSuccessCount = 0;
        long difficultStartNanos = System.nanoTime();

        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(currentProgram);
        decompiler.setOptions(options);
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException("Decompiler initialization failed: " + decompiler.getLastMessage());
        }

        try (BufferedWriter bodies = Files.newBufferedWriter(
                output.resolve("bodies.ndjson"), StandardCharsets.UTF_8);
             BufferedWriter references = Files.newBufferedWriter(
                output.resolve("references.ndjson"), StandardCharsets.UTF_8)) {
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                monitor.checkCancelled();
                Function function = functions.next();
                Address entry = function.getEntryPoint();
                MemoryBlock entryBlock = currentProgram.getMemory().getBlock(entry);
                if (function.isExternal() || entryBlock == null || !entryBlock.isExecute()) {
                    continue;
                }

                String stem = String.format("function-%08d", ordinal);
                ordinal++;
                attributed.add(function.getBody());
                MessageDigest bodyDigest = MessageDigest.getInstance("SHA-256");
                StringBuilder assembly = new StringBuilder();
                InstructionIterator instructions = currentProgram.getListing().getInstructions(
                    function.getBody(), true);
                long instructionCount = 0;
                long bodyByteCount = 0;
                long unresolvedCallCount = 0;
                long referenceCount = 0;
                while (instructions.hasNext()) {
                    Instruction instruction = instructions.next();
                    byte[] bytes = instruction.getBytes();
                    bodyDigest.update(bytes);
                    instructionCount++;
                    bodyByteCount += bytes.length;
                    long instructionRva = relative(instruction.getAddress(), imageBase);
                    assembly.append(String.format(
                        "%016x  %-32s  %s%n",
                        instructionRva,
                        hex(bytes),
                        instruction.toString()));

                    boolean resolvedCall = false;
                    for (Reference reference : instruction.getReferencesFrom()) {
                        if (!reference.getReferenceType().isCall() &&
                            !reference.getReferenceType().isData()) {
                            continue;
                        }
                        Address target = reference.getToAddress();
                        String targetRva = null;
                        if (target != null && target.getAddressSpace().equals(imageBase.getAddressSpace())) {
                            try {
                                targetRva = String.format("0x%x", relative(target, imageBase));
                            }
                            catch (IllegalArgumentException ignored) {
                                targetRva = null;
                            }
                        }
                        if (reference.getReferenceType().isCall()) {
                            resolvedCall = target != null;
                        }
                        references.write("{" +
                            "\"source_ordinal\":" + (ordinal - 1) + "," +
                            "\"source_instruction_rva\":" + json(String.format("0x%x", instructionRva)) + "," +
                            "\"kind\":" + json(reference.getReferenceType().isCall() ? "direct_call" : "data") + "," +
                            "\"target_address\":" + json(target == null ? null : target.toString()) + "," +
                            "\"target_rva\":" + json(targetRva) +
                            "}\n");
                        referenceCount++;
                    }
                    if (instruction.getFlowType().isCall() && !resolvedCall) {
                        references.write("{" +
                            "\"source_ordinal\":" + (ordinal - 1) + "," +
                            "\"source_instruction_rva\":" + json(String.format("0x%x", instructionRva)) + "," +
                            "\"kind\":\"unresolved_call\"," +
                            "\"target_address\":null," +
                            "\"target_rva\":null," +
                            "\"raw_operand\":" + json(instruction.toString()) +
                            "}\n");
                        unresolvedCallCount++;
                        referenceCount++;
                    }
                }

                String status;
                String diagnostic = null;
                String cRelative = null;
                String asmRelative = null;
                if (instructionCount == 0) {
                    status = "disassembly_failed";
                    diagnostic = "no_instructions_in_function_body";
                    disassemblyFailedCount++;
                }
                else {
                    Path assemblyPath = assemblyRoot.resolve(stem + ".asm");
                    Files.writeString(assemblyPath, assembly.toString(), StandardCharsets.UTF_8);
                    asmRelative = output.relativize(assemblyPath).toString().replace('\\', '/');
                    if (timeoutCount >= maximumTimeouts) {
                        status = "pending";
                        diagnostic = "primary_timeout_budget_exhausted";
                        pendingCount++;
                    }
                    else {
                        try {
                            DecompileResults result = decompiler.decompileFunction(
                                function, timeoutSeconds, monitor);
                            if (result.isTimedOut()) {
                                timeoutCount++;
                                long difficultElapsedSeconds =
                                    (System.nanoTime() - difficultStartNanos) / 1_000_000_000L;
                                if (difficultAttemptCount < maximumDifficultBodies &&
                                    difficultElapsedSeconds < maximumDifficultWallSeconds) {
                                    int remainingSeconds = (int) Math.max(
                                        1L, maximumDifficultWallSeconds - difficultElapsedSeconds);
                                    int retryTimeout = Math.min(
                                        difficultTimeoutSeconds, remainingSeconds);
                                    difficultAttemptCount++;
                                    DecompileResults difficultResult = decompiler.decompileFunction(
                                        function, retryTimeout, monitor);
                                    DecompiledFunction difficultFunction =
                                        difficultResult.getDecompiledFunction();
                                    String difficultC = difficultFunction == null ?
                                        null : difficultFunction.getC();
                                    if (!difficultResult.isTimedOut() &&
                                        difficultResult.decompileCompleted() &&
                                        validC(difficultC)) {
                                        Path cPath = cRoot.resolve(stem + ".c");
                                        Files.writeString(
                                            cPath, difficultC, StandardCharsets.UTF_8);
                                        cRelative = output.relativize(cPath)
                                            .toString().replace('\\', '/');
                                        status = "c_and_asm";
                                        diagnostic = "primary_timeout_difficult_retry_succeeded";
                                        difficultSuccessCount++;
                                        cCount++;
                                    }
                                    else {
                                        status = "asm_only";
                                        diagnostic = difficultResult.isTimedOut() ?
                                            "primary_and_difficult_timeout" :
                                            "primary_timeout_difficult_retry_failed: " +
                                                difficultResult.getErrorMessage();
                                        asmOnlyCount++;
                                    }
                                }
                                else {
                                    status = "asm_only";
                                    diagnostic = "decompiler_timeout_difficult_budget_exhausted";
                                    asmOnlyCount++;
                                }
                            }
                            else if (!result.decompileCompleted()) {
                                status = "asm_only";
                                diagnostic = result.getErrorMessage();
                                asmOnlyCount++;
                            }
                            else {
                                DecompiledFunction decompiled = result.getDecompiledFunction();
                                String c = decompiled == null ? null : decompiled.getC();
                                if (validC(c)) {
                                    Path cPath = cRoot.resolve(stem + ".c");
                                    Files.writeString(cPath, c, StandardCharsets.UTF_8);
                                    cRelative = output.relativize(cPath).toString().replace('\\', '/');
                                    status = "c_and_asm";
                                    diagnostic = result.getErrorMessage();
                                    cCount++;
                                }
                                else {
                                    status = "asm_only";
                                    diagnostic = "empty_truncated_or_error_c";
                                    asmOnlyCount++;
                                }
                            }
                        }
                        catch (Exception exception) {
                            status = "asm_only";
                            diagnostic = exception.getClass().getName() + ": " + exception.getMessage();
                            asmOnlyCount++;
                        }
                    }
                }

                bodies.write("{" +
                    "\"ordinal\":" + (ordinal - 1) + "," +
                    "\"entry_address\":" + json(entry.toString()) + "," +
                    "\"rva\":" + json(String.format("0x%x", relative(entry, imageBase))) + "," +
                    "\"name\":" + json(function.getName()) + "," +
                    "\"namespace\":" + json(function.getParentNamespace().getName(true)) + "," +
                    "\"symbol_source\":" + json(function.getSymbol().getSource().toString().toLowerCase()) + "," +
                    "\"calling_convention\":" + json(function.getCallingConventionName()) + "," +
                    "\"native_prototype\":" + json(function.getPrototypeString(true, true)) + "," +
                    "\"raw_body_hash\":" + json(digestHex(bodyDigest)) + "," +
                    "\"instruction_count\":" + instructionCount + "," +
                    "\"body_byte_count\":" + bodyByteCount + "," +
                    "\"reference_count\":" + referenceCount + "," +
                    "\"unresolved_call_count\":" + unresolvedCallCount + "," +
                    "\"body_output_status\":" + json(status) + "," +
                    "\"asm_path\":" + json(asmRelative) + "," +
                    "\"c_path\":" + json(cRelative) + "," +
                    "\"diagnostic\":" + json(diagnostic) +
                    "}\n");
            }
        }
        finally {
            decompiler.dispose();
        }

        AddressSet executable = new AddressSet();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (block.isExecute() && block.isInitialized()) {
                executable.addRange(block.getStart(), block.getEnd());
            }
        }
        executable.delete(attributed);
        try (BufferedWriter ranges = Files.newBufferedWriter(
                output.resolve("unattributed-ranges.ndjson"), StandardCharsets.UTF_8)) {
            AddressRangeIterator iterator = executable.getAddressRanges(true);
            while (iterator.hasNext()) {
                AddressRange range = iterator.next();
                ranges.write("{" +
                    "\"start_rva\":" + json(String.format("0x%x", relative(range.getMinAddress(), imageBase))) + "," +
                    "\"end_rva\":" + json(String.format("0x%x", relative(range.getMaxAddress(), imageBase))) + "," +
                    "\"size_bytes\":" + range.getLength() +
                    "}\n");
            }
        }

        String summary = "{" +
            "\"schema_version\":1," +
            "\"program_name\":" + json(currentProgram.getName()) + "," +
            "\"executable_sha256\":" + json(currentProgram.getExecutableSHA256()) + "," +
            "\"language_id\":" + json(currentProgram.getLanguageID().toString()) + "," +
            "\"compiler_spec_id\":" + json(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) + "," +
            "\"image_base\":" + json(imageBase.toString()) + "," +
            "\"function_count\":" + ordinal + "," +
            "\"c_and_asm\":" + cCount + "," +
            "\"asm_only\":" + asmOnlyCount + "," +
            "\"disassembly_failed\":" + disassemblyFailedCount + "," +
            "\"pending\":" + pendingCount + "," +
            "\"primary_timeout_count\":" + timeoutCount + "," +
            "\"difficult_attempt_count\":" + difficultAttemptCount + "," +
            "\"difficult_success_count\":" + difficultSuccessCount +
            "}\n";
        Files.writeString(output.resolve("summary.json"), summary, StandardCharsets.UTF_8);
        println("ANIIMO_EXPORT_SUMMARY " + summary.strip());
    }
}
