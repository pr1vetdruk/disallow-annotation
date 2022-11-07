package ru.somsin.disallowtransaction.visitor;

import org.objectweb.asm.*;
import org.objectweb.asm.commons.Method;
import ru.somsin.disallowtransaction.annotation.DisallowTransaction;
import ru.somsin.disallowtransaction.model.MethodData;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;

/**
 * Visitor for disallow transaction
 */
public class DisallowTransactionVisitor {
    private final String INIT = "<init>";
    private final String CL_INIT = "<clinit>";
    private final String DOT_CLASS = ".class";

    private Class<? extends Annotation> annotationClass;
    private String targetClass;
    private Method targetMethod;

    private DisallowTransactionClassVisitor classVisitor;

    private final List<Path> pathsToClasses = new ArrayList<>();
    private final Set<Node> roots = new HashSet<>();
    private final Map<java.lang.reflect.Method, Set<Node>> invokeDynamic = new HashMap<>();

    private boolean foundTransactional = false;

    /**
     * Run a check
     *
     * @throws Exception In case of errors
     */
    public void run() throws Exception {
        definePathsToClasses();
        determineRoots();
        determineNodes();
    }

    /**
     * Roots get
     *
     * @return Set of nodes
     */
    public Set<Node> getRoots() {
        return roots;
    }


    /**
     * Transaction indication
     *
     * @return true if it has
     */
    public boolean isFoundTransactional() {
        return foundTransactional;
    }

    private static class Node {
        private final Class<?> clazz;
        private final MethodData methodData;
        private final Set<Node> nodes = new HashSet<>();

        public Node(Class<?> clazz, MethodData methodData) {
            this.clazz = clazz;
            this.methodData = methodData;
        }

        public Class<?> getClazz() {
            return clazz;
        }

        public MethodData getMethodData() {
            return methodData;
        }

        public Set<Node> getNodes() {
            return nodes;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Node node = (Node) o;
            return Objects.equals(clazz, node.clazz) && Objects.equals(methodData, node.methodData);
        }

        @Override
        public int hashCode() {
            return Objects.hash(clazz, methodData);
        }
    }

    private Class<?>[] determineParameters(String descriptor) {
        Type[] argumentTypes = Type.getArgumentTypes(descriptor);
        List<Class<?>> parameters = new ArrayList<>(argumentTypes.length);

        for (Type type : argumentTypes) {
            switch (type.getSort()) {
                case Type.ARRAY:
                    try {
                        parameters.add(Class.forName(type.getDescriptor().replace('/', '.')));
                    } catch (ClassNotFoundException e) {
                        throw new RuntimeException(e);
                    }
                    break;
                case Type.BOOLEAN:
                    parameters.add(boolean.class);
                    break;
                case Type.BYTE:
                    parameters.add(byte.class);
                    break;
                case Type.CHAR:
                    parameters.add(char.class);
                    break;
                case Type.SHORT:
                    parameters.add(short.class);
                    break;
                case Type.INT:
                    parameters.add(int.class);
                    break;
                case Type.FLOAT:
                    parameters.add(float.class);
                    break;
                case Type.DOUBLE:
                    parameters.add(double.class);
                    break;
                case Type.LONG:
                    parameters.add(long.class);
                    break;
                default:
                    try {
                        parameters.add(Class.forName(type.getClassName()));
                    } catch (ClassNotFoundException e) {
                        throw new RuntimeException(e);
                    }
                    break;
            }
        }

        return parameters.toArray(new Class[]{});
    }

    private class DisallowTransactionClassVisitor extends ClassVisitor {
        private final DisallowTransactionMethodVisitor methodVisitor = new DisallowTransactionMethodVisitor();

        private Class<?> clazz;
        private java.lang.reflect.Method method;
        private Node node;

        private final boolean determineRootNodes;

        public DisallowTransactionClassVisitor(boolean determineRootNodes, Node node) {
            super(Opcodes.ASM9);
            this.determineRootNodes = determineRootNodes;
            this.node = node;
        }

        public DisallowTransactionClassVisitor(boolean determineRootNodes) {
            super(Opcodes.ASM9);
            this.determineRootNodes = determineRootNodes;
        }

        @Override
        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            try {
                clazz = Class.forName(Type.getObjectType(name).getClassName());
            } catch (ClassNotFoundException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            if (INIT.equals(name) || CL_INIT.equals(name)) {
                return null;
            }

            try {
                method = clazz.getDeclaredMethod(name, determineParameters(descriptor));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            if (!determineRootNodes) {
                return methodVisitor;
            }

            boolean hasTransactional = false;
            boolean hasDisallowTransaction = false;

            for (Annotation annotation : method.getDeclaredAnnotations()) {
                Class<? extends Annotation> annotationType = annotation.annotationType();

                if (annotationType.equals(DisallowTransaction.class)) {
                    hasDisallowTransaction = true;
                } else if (annotationType.equals(annotationClass)) {
                    hasTransactional = true;
                }
            }

            if (hasDisallowTransaction) {
                MethodData methodData = new MethodData(method, hasTransactional);
                Node node = new Node(clazz, methodData);
                roots.add(node);
            }

            return methodVisitor;
        }

        private class DisallowTransactionMethodVisitor extends MethodVisitor {
            public DisallowTransactionMethodVisitor() {
                super(Opcodes.ASM9);
            }

            @Override
            public void visitInvokeDynamicInsn(String name, String descriptor, Handle bootstrapMethodHandle, Object... bootstrapMethodArguments) {
                if (!classVisitor.determineRootNodes) {
                    return;
                }

                for (Object bootstrapMethodArgument : bootstrapMethodArguments) {
                    if (bootstrapMethodArgument instanceof Handle) {
                        Handle handle = (Handle) bootstrapMethodArgument;
                        boolean hasTransactional = false;

                        for (Annotation annotation : method.getDeclaredAnnotations()) {
                            if (annotation.annotationType().equals(annotationClass)) {
                                hasTransactional = true;
                                break;
                            }
                        }

                        MethodData methodData = new MethodData(method, hasTransactional);
                        Node node = new Node(clazz, methodData);

                        Class<?> invokeClass;
                        try {
                            invokeClass = Class.forName(Type.getObjectType(handle.getOwner()).getClassName());
                        } catch (ClassNotFoundException e) {
                            throw new RuntimeException(e);
                        }

                        java.lang.reflect.Method invokeMethod;
                        try {
                            invokeMethod = invokeClass.getDeclaredMethod(handle.getName(), determineParameters(handle.getDesc()));
                        } catch (NoSuchMethodException e) {
                            throw new RuntimeException(e);
                        }
                        Set<Node> nodes = invokeDynamic.get(invokeMethod);

                        if (nodes == null || nodes.size() == 0) {
                            nodes = new HashSet<>();
                            invokeDynamic.put(invokeMethod, nodes);
                        }

                        nodes.add(node);
                    }
                }

                super.visitInvokeDynamicInsn(name, descriptor, bootstrapMethodHandle, bootstrapMethodArguments);
            }

            @Override
            public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
                if (owner.equals(targetClass)
                        && name.equals(targetMethod.getName())
                        && descriptor.equals(targetMethod.getDescriptor())) {
                    boolean hasTransactional = false;

                    for (Annotation annotation : method.getDeclaredAnnotations()) {
                        if (annotation.annotationType().equals(annotationClass)) {
                            hasTransactional = true;
                        }
                    }

                    MethodData methodData = new MethodData(method, hasTransactional);
                    Node newNode = new Node(clazz, methodData);

                    node.getNodes().add(newNode);
                }
            }
        }
    }

    private void determineNodes() throws Exception {
        for (Node root : roots) {
            determineNodes(root);
        }
    }

    private void definePathsToClasses() throws IOException {
        Files.walkFileTree(Paths.get("build", "classes", "java", "main"), new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) {
                String fileName = file.getFileName().toString();

                if (fileName.endsWith(DOT_CLASS)) {
                    pathsToClasses.add(file);
                }

                return FileVisitResult.CONTINUE;
            }
        });
    }

    private void determineRoots() throws IOException {
        classVisitor = new DisallowTransactionClassVisitor(true);
        acceptStream(pathsToClasses);
    }

    private void determineNodes(Node root) throws Exception {
        determineInnerNodes(root);

        for (Node node : root.getNodes()) {
            if (node.getMethodData().isHasTransactional()) {
                foundTransactional = true;
            }

            determineNodes(node);
        }
    }

    private void determineInnerNodes(Node node) throws Exception {
        targetClass = node.getClazz().getName().replace('.', '/');
        targetMethod = Method.getMethod(node.getMethodData().getMethod());
        classVisitor = new DisallowTransactionClassVisitor(false, node);

        acceptStream(pathsToClasses);

        java.lang.reflect.Method method = node.getMethodData().getMethod();
        Set<Node> nodes = invokeDynamic.get(method);

        if (nodes != null) {
            node.getNodes().addAll(nodes);
        }
    }

    private void acceptStream(List<Path> pathsToClasses) throws IOException {
        for (Path path : pathsToClasses) {
            try (InputStream stream = new BufferedInputStream(Files.newInputStream(path))) {
                new ClassReader(stream).accept(classVisitor, 0);
            }
        }
    }
}
